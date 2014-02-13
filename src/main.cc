/**
 * @file    main.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   obfsclient main entry point
 */

/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <list>
#include <memory>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <allium.h>
#include <event2/event.h>

#include "schwanenlied/common.h"
#include "schwanenlied/socks5_server.h"
#include "schwanenlied/pt/obfs2/client.h"
#include "schwanenlied/pt/obfs3/client.h"
#include "schwanenlied/pt/scramblesuit/client.h"

using Socks5Server = schwanenlied::Socks5Server;
using Socks5Factory = schwanenlied::Socks5Server::SessionFactory;
using Obfs2Factory = schwanenlied::pt::obfs2::Client::SessionFactory;
using Obfs3Factory = schwanenlied::pt::obfs3::Client::SessionFactory;
using ScrambleSuitFactory = schwanenlied::pt::scramblesuit::Client::SessionFactory;

static constexpr char kObfs2MethodName[] = "obfs2";
static constexpr char kObfs3MethodName[] = "obfs3";
static constexpr char kScrambleSuitMethodName[] = "scramblesuit";
static struct event_base* ev_base = nullptr;

static bool init_libevent() {
  if (ev_base == nullptr)
    ev_base = ::event_base_new();

  return ev_base != nullptr;
}

template<class Factory>
static bool init_pt(const allium_ptcfg* cfg,
                    const char* name,
                    ::std::list<::std::unique_ptr<Socks5Factory>>& factories,
                    ::std::list<::std::unique_ptr<Socks5Server>>& listeners) {
  if (::allium_ptcfg_method_requested(cfg, kObfs3MethodName) != 1)
    return false;

  if (!init_libevent()) {
    ::allium_ptcfg_method_error(cfg, name, "event_base_new()");
    return false;
  }

  Factory* factory = new Factory;
  Socks5Server* listener = new Socks5Server(factory, ev_base);
  if (!listener->bind()) {
    ::allium_ptcfg_method_error(cfg, name, "Socks5::bind()");
out_free:
    delete factory;
    delete listener;
    return false;
  }

  struct sockaddr_in socks_addr;
  if (!listener->addr(socks_addr)) {
    ::allium_ptcfg_method_error(cfg, name, "Socks5::addr()");
    goto out_free;
  }

  factories.push_back(::std::unique_ptr<Socks5Factory>(factory));
  listeners.push_back(::std::unique_ptr<Socks5Server>(listener));

  ::allium_ptcfg_cmethod_report(cfg, name, 5,
                                reinterpret_cast<struct sockaddr*>(&socks_addr),
                                sizeof(socks_addr), nullptr, nullptr);

  return true;
}

int main(int argc, char* argv[]) {
  ::std::list<::std::unique_ptr<Socks5Factory>> factories;
  ::std::list<::std::unique_ptr<Socks5Server>> listeners;
  allium_ptcfg* cfg;

  cfg = ::allium_ptcfg_init();
  if (!cfg)
    return -1;

  if (::allium_ptcfg_is_server(cfg)) {
    ::allium_ptcfg_methods_done(cfg);
    ::allium_ptcfg_free(cfg);
    return -1;
  }

  // Attempt to initialize the supported PTs
  bool dispatch_loop = false;
  dispatch_loop |= init_pt<Obfs3Factory>(cfg, kObfs3MethodName, factories,
                                         listeners);
  dispatch_loop |= init_pt<Obfs2Factory>(cfg, kObfs2MethodName, factories,
                                         listeners);
  dispatch_loop |= init_pt<ScrambleSuitFactory>(cfg, kScrambleSuitMethodName,
                                                factories, listeners);

  // Done with the config!
  ::allium_ptcfg_methods_done(cfg);
  ::allium_ptcfg_free(cfg);

  SL_ASSERT(factories.size() == listeners.size());
  if (dispatch_loop) {
    // TODO: Install a SIGINT handler (Tor just kills us anyway)

    // Mask off SIGPIPE
    ::signal(SIGPIPE, SIG_IGN);

    // Run the event loop
    ::event_base_dispatch(ev_base);
  }

  return 0;
}
