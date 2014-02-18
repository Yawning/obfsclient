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
#include <unistd.h>

#include <allium/allium.h>
#include <event2/event.h>

#include "schwanenlied/common.h"
#include "schwanenlied/socks5_server.h"
#include "schwanenlied/pt/obfs2/client.h"
#include "schwanenlied/pt/obfs3/client.h"
#include "schwanenlied/pt/scramblesuit/client.h"

_INITIALIZE_EASYLOGGINGPP

using Socks5Server = schwanenlied::Socks5Server;
using Socks5Factory = schwanenlied::Socks5Server::SessionFactory;
using Obfs2Factory = schwanenlied::pt::obfs2::Client::SessionFactory;
using Obfs3Factory = schwanenlied::pt::obfs3::Client::SessionFactory;
using ScrambleSuitFactory = schwanenlied::pt::scramblesuit::Client::SessionFactory;

static constexpr char kLogFileName[] = "obfsclient.log";
static constexpr char kLogger[] = "main";

static constexpr char kObfs2MethodName[] = "obfs2";
static constexpr char kObfs3MethodName[] = "obfs3";
static constexpr char kScrambleSuitMethodName[] = "scramblesuit";

static struct event_base* ev_base = nullptr;

static bool init_statedir(const allium_ptcfg* cfg,
                          ::std::string& path) {
  size_t len = 0;
  ::allium_ptcfg_state_dir(cfg, nullptr, &len);
  ::std::unique_ptr<char> tmp(new char[len]);
  if (0 != ::allium_ptcfg_state_dir(cfg, tmp.get(), &len))
    return false;

  path.assign(tmp.get());
  return true;
}

static void init_logging(const bool enabled,
                         const ::std::string& path,
                         const bool debug) {
  ::el::Configurations conf;
  conf.setToDefault();
  if (enabled) {
    // Ok, there's a state directory, enable logging
    conf.setToDefault();
    conf.setGlobally(::el::ConfigurationType::ToStandardOutput, "false");
    conf.setGlobally(::el::ConfigurationType::Filename,
                     path + ::std::string(kLogFileName));
    conf.set(::el::Level::Debug, ::el::ConfigurationType::Format,
             "%datetime %level [%logger] %msg");
    if (!debug)
      conf.set(::el::Level::Debug, ::el::ConfigurationType::Enabled, "false");
    ::el::Helpers::addFlag(el::LoggingFlag::ImmediateFlush);
  } else
    conf.setGlobally(::el::ConfigurationType::Enabled, "false");
  ::el::Loggers::setDefaultConfigurations(conf, true);
  (void)::el::Loggers::getLogger(kLogger);
}

static bool init_libevent() {
  if (ev_base == nullptr)
    ev_base = ::event_base_new();

  return ev_base != nullptr;
}

template<class Factory>
static bool init_pt(const allium_ptcfg* cfg,
                    const char* name,
                    ::std::list<::std::unique_ptr<Socks5Factory>>& factories,
                    ::std::list<::std::unique_ptr<Socks5Server>>& listeners,
                    const bool scrub_addrs = true) {
  if (::allium_ptcfg_method_requested(cfg, name) != 1)
    return false;

  if (!init_libevent()) {
    CLOG(ERROR, kLogger) << "Failed to initialize a libevent event_base";
    ::allium_ptcfg_method_error(cfg, name, "event_base_new()");
    return false;
  }

  Factory* factory = new Factory;
  Socks5Server* listener = new Socks5Server(factory, ev_base, scrub_addrs);
  if (!listener->bind()) {
    CLOG(ERROR, kLogger) << "Failed to bind() a SOCKSv5 listener";
    ::allium_ptcfg_method_error(cfg, name, "Socks5::bind()");
out_free:
    delete factory;
    delete listener;
    return false;
  }

  struct sockaddr_in socks_addr;
  if (!listener->addr(socks_addr)) {
    CLOG(ERROR, kLogger) << "Failed to query the SOCKSv5 address";
    ::allium_ptcfg_method_error(cfg, name, "Socks5::addr()");
    goto out_free;
  }

  factories.push_back(::std::unique_ptr<Socks5Factory>(factory));
  listeners.push_back(::std::unique_ptr<Socks5Server>(listener));

  CLOG(INFO, kLogger) << "SOCKSv5 Listener: "
                      << Socks5Server::addr_to_string(reinterpret_cast<struct
                                                      sockaddr*>(&socks_addr),
                                                      false)
                      << " " << name ;

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

  // Determine the state directory and initialize logging
  ::std::string state_dir;
  const bool has_state_dir = init_statedir(cfg, state_dir);
  init_logging(has_state_dir, state_dir, false); // No debug logs for now

  // Log a banner
  CLOG(INFO, kLogger) << "obfsclient - Initialized (PID: " << ::getpid() << ")";

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
    CLOG(INFO, kLogger) << "Awaiting incoming connections";
    ::event_base_dispatch(ev_base);
  } else
    CLOG(INFO, kLogger) << "No supported transports found, exiting";

  return 0;
}
