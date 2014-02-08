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
#include "schwanenlied/pt/obfs2client.h"
#include "schwanenlied/pt/obfs3client.h"

using Socks5Server = schwanenlied::Socks5Server;
using Socks5Factory = schwanenlied::Socks5Server::SessionFactory;
using Obfs2Factory = schwanenlied::pt::Obfs2Client::SessionFactory;
using Obfs3Factory = schwanenlied::pt::Obfs3Client::SessionFactory;

static const char kObfs2MethodName[] = "obfs2";
static const char kObfs3MethodName[] = "obfs3";
static struct event_base* ev_base = nullptr;

static bool init_libevent() {
  if (ev_base == nullptr)
    ev_base = ::event_base_new();

  return ev_base != nullptr;
}

int main(int argc, char* argv[]) {
  ::std::list<::std::unique_ptr<Socks5Factory>> factories;
  ::std::list<::std::unique_ptr<Socks5Server>> listeners;
  allium_ptcfg* cfg;

  cfg = ::allium_ptcfg_init();
  if (!cfg)
    return -1;

  if (::allium_ptcfg_is_server(cfg)) {
out_error:
    ::allium_ptcfg_methods_done(cfg);
    ::allium_ptcfg_free(cfg);
    return -1;
  }

  // Attempt to configure obfs3
  int rval = ::allium_ptcfg_method_requested(cfg, kObfs3MethodName);
  if (rval == 1) {
    if (!init_libevent()) {
      ::allium_ptcfg_method_error(cfg, kObfs3MethodName, "event_base_new()");
      goto out_error;
    }

    Obfs3Factory* factory = new Obfs3Factory;
    Socks5Server* listener = new Socks5Server(factory, ev_base);
    if (!listener->bind()) {
      ::allium_ptcfg_method_error(cfg, kObfs3MethodName, "Socks5::bind()");
out_free_obfs3:
      delete factory;
      delete listener;
      goto try_obfs2;
    }

    struct sockaddr_in socks_addr;
    if (!listener->addr(socks_addr)) {
      ::allium_ptcfg_method_error(cfg, kObfs3MethodName, "Socks5::addr()");
      goto out_free_obfs3;
    }

    factories.push_back(::std::unique_ptr<Socks5Factory>(factory));
    listeners.push_back(::std::unique_ptr<Socks5Server>(listener));

    ::allium_ptcfg_cmethod_report(cfg, kObfs3MethodName, 5,
                                  reinterpret_cast<struct sockaddr*>(&socks_addr),
                                  sizeof(socks_addr), nullptr, nullptr);
  }

  // Attempt to configure obfs2
try_obfs2:
  rval = ::allium_ptcfg_method_requested(cfg, kObfs2MethodName);
  if (rval == 1) {
    if (!init_libevent()) {
      ::allium_ptcfg_method_error(cfg, kObfs2MethodName, "event_base_new()");
      goto out_error;
    }

    Obfs2Factory* factory = new Obfs2Factory;
    Socks5Server* listener = new Socks5Server(factory, ev_base);
    if (!listener->bind()) {
      ::allium_ptcfg_method_error(cfg, kObfs2MethodName, "Socks5::bind()");
out_free_obfs2:
      delete factory;
      delete listener;
      goto done;
    }

    struct sockaddr_in socks_addr;
    if (!listener->addr(socks_addr)) {
      ::allium_ptcfg_method_error(cfg, kObfs2MethodName, "Socks5::addr()");
      goto out_free_obfs2;
    }

    factories.push_back(::std::unique_ptr<Socks5Factory>(factory));
    listeners.push_back(::std::unique_ptr<Socks5Server>(listener));

    ::allium_ptcfg_cmethod_report(cfg, kObfs2MethodName, 5,
                                  reinterpret_cast<struct sockaddr*>(&socks_addr),
                                  sizeof(socks_addr), nullptr, nullptr);
  }

  // Done with the config!
done:
  ::allium_ptcfg_methods_done(cfg);
  ::allium_ptcfg_free(cfg);

  SL_ASSERT(factories.size() == listeners.size());
  if (listeners.size() > 0) {
    // TODO: Install a SIGINT handler (Tor just kills us anyway)

    // Mask off SIGPIPE
    ::signal(SIGPIPE, SIG_IGN);

    // Run the event loop
    ::event_base_dispatch(ev_base);
  }

  return 0;
}
