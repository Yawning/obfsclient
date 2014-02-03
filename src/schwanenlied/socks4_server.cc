/**
 * @file    socks4_server.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SOCKSv4 Server (IMPLEMENTATION)
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

#include <cstring>

#include <event2/buffer.h>
#include <event2/util.h>

#include "schwanenlied/socks4_server.h"

namespace schwanenlied {

Socks4Server::~Socks4Server() {
  close();
}

const bool Socks4Server::addr(struct sockaddr_in& addr) const {
  if (listener_ == nullptr)
    return false;

  ::std::memcpy(&addr, &listener_addr_, sizeof(addr));

  return true;
}

bool Socks4Server::bind() {
  if (listener_ != nullptr)
    return false;

  // Initialize a sockaddr for the server socket
  listener_addr_.sin_family = AF_INET;
  listener_addr_.sin_port = 0;
  evutil_inet_pton(AF_INET, "127.0.0.1", &listener_addr_.sin_addr);

  // Initialize the on connect callback, shamelessly abusing a lambda
  evconnlistener_cb cb = [](struct evconnlistener* listener,
                            evutil_socket_t sock,
                            struct sockaddr* addr,
                            int len,
                            void* ptr) {
    reinterpret_cast<Socks4Server*>(ptr)->on_new_connection(sock, addr, len);
  };

  listener_ = ::evconnlistener_new_bind(base_, cb, this,
                                        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                        -1, reinterpret_cast<struct sockaddr*>(&listener_addr_),
                                        sizeof(listener_addr_));
  if (listener_ == nullptr)
    return false;

  // Query the port that end up bound
  const evutil_socket_t sock = ::evconnlistener_get_fd(listener_);
  socklen_t len = sizeof(listener_addr_);
  int rval = ::getsockname(sock, reinterpret_cast<struct sockaddr*>(&listener_addr_),
                           &len);
  if (rval != 0)
    return false;

  return true;
}

void Socks4Server::close() {
  if (listener_ != nullptr) {
    ::evconnlistener_free(listener_);
    listener_ = nullptr;
  }
}

void Socks4Server::on_new_connection(evutil_socket_t sock,
                                     struct sockaddr* addr,
                                     int addr_len) {
  /*
   * Yes, this may look like it's leaking memory, but, there's libevent goodness
   * that holds a pointer to the Session object as the opaque callback arg.
   */

  Session* session = factory_->create_session(base_, sock, addr, addr_len);
  if (session == nullptr)
    evutil_closesocket(sock);
}

Socks4Server::Session::Session(struct event_base* base,
                               const evutil_socket_t sock,
                               const struct sockaddr* addr,
                               const int addr_len) :
    base_(base),
    incoming_(nullptr),
    outgoing_(nullptr),
    remote_addr_(),
    state_(State::kREAD_REQUEST),
    incoming_valid_(false),
    outgoing_valid_(false) {
  incoming_ = ::bufferevent_socket_new(base_, sock, BEV_OPT_CLOSE_ON_FREE);
  SL_ASSERT(incoming_ != nullptr);

  // Initialize the callbacks for the incoming socket
  bufferevent_data_cb readcb = [](struct bufferevent *bev,
                                  void *ctx) {
    reinterpret_cast<Session*>(ctx)->incoming_read_cb();
  };
  bufferevent_data_cb writecb = [](struct bufferevent *bev,
                                   void *ctx) {
    reinterpret_cast<Session*>(ctx)->incoming_write_cb();
  };
  bufferevent_event_cb eventcb = [](struct bufferevent *bev,
                                    short events,
                                    void *ctx) {
    reinterpret_cast<Session*>(ctx)->incoming_event_cb(events);
  };
  ::bufferevent_setcb(incoming_, readcb, writecb, eventcb, this);
  ::bufferevent_enable(incoming_, EV_READ | EV_WRITE);
  incoming_valid_ = true;
}

Socks4Server::Session::~Session() {
  if (outgoing_ != nullptr)
    bufferevent_free(outgoing_);
  if (incoming_ != nullptr)
    bufferevent_free(incoming_);
}

void Socks4Server::Session::send_socks4_response(const bool success) {
  uint8_t response[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  if (success) {
    // All further data should be handled filtered and relayed
    state_ = State::kESTABLISHED;
    response[1] = 0x5a; // CD: Request granted
  } else {
    // Want to close as soon as the buffer is empty
    outgoing_valid_ = false;
    state_ = State::kFLUSHING_INCOMING;
    response[1] = 0x5b; // CD: Request failed
  }

  int ret = ::bufferevent_write(incoming_, response, sizeof(response));
  SL_ASSERT(ret == 0);
  if (success)
    ::bufferevent_enable(incoming_, EV_READ);
}

void Socks4Server::Session::incoming_read_cb() {
  if (!incoming_valid_)
    return;

  switch (state_) {
  case State::kREAD_REQUEST:
  {
    // Parse the SOCKSv4 request
    SL_ASSERT(!outgoing_valid_);
    struct evbuffer* buf = ::bufferevent_get_input(incoming_);
    const size_t len = ::evbuffer_get_length(buf);
    if (len < 9)
      return;

    uint8_t* p = ::evbuffer_pullup(buf, 9);
    if (p == nullptr) {
out_free:
      delete this;
      return;
    }

    // Ensure that SOCKSv4 is requested
    if (p[0] != 0x04)
      goto out_free;

    // Ensure that a TCP/IP stream is requested
    if (p[1] != 0x01)
      goto out_free;

    // This implementation doesn't support arguments yet
    if (p[8] != 0x00)
      goto out_free;

    // It's really simple, don't fucking send trailing bullshit
    ::evbuffer_drain(buf, 9);
    if (::evbuffer_get_length(buf) != 0)
      goto out_free;

    // Pull out the address/port and connect
    remote_addr_.sin_family = AF_INET;
    remote_addr_.sin_port = *reinterpret_cast<uint16_t*>(p + 2);
   	remote_addr_.sin_addr.s_addr = *reinterpret_cast<uint32_t*>(p + 4);
    if (!outgoing_connect())
      goto out_free;

    ::bufferevent_disable(incoming_, EV_READ);
    break;
  }
  case State::kESTABLISHED:
    // Pass it onto the filter
    if (!outgoing_valid_)
      return;
    on_incoming_data();
    break;
  default:
    SL_ABORT();
  }
}

void Socks4Server::Session::incoming_write_cb() {
  if (state_ == State::kESTABLISHED)
    on_incoming_drained();
  else if (state_ == State::kFLUSHING_INCOMING)
    delete this;
}

void Socks4Server::Session::incoming_event_cb(const short events) {
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    incoming_valid_ = false;
    const struct evbuffer* buf = ::bufferevent_get_output(outgoing_);
    if (!outgoing_valid_ || ::evbuffer_get_length(buf) == 0) {
      // Outgoing is invalid or fully flushed, done!
      delete this;
    } else {
      // Need to attempt to flush outgoing first
      ::bufferevent_disable(incoming_, EV_READ);
      state_ = State::kFLUSHING_OUTGOING;
    }
  }
}

void Socks4Server::Session::outgoing_read_cb() {
  if (!outgoing_valid_)
    return;

  switch (state_) {
  case State::kCONNECTING:
    on_outgoing_data_connecting();
    break;
  case State::kESTABLISHED:
    // Pass it onto the filter
    if (!incoming_valid_)
      return;
    on_outgoing_data();
    break;
  default:
    SL_ABORT();
  }
}

void Socks4Server::Session::outgoing_write_cb() {
  if (state_ == State::kCONNECTING || state_ == State::kESTABLISHED)
    on_outgoing_drained();
  else if (state_ == State::kFLUSHING_OUTGOING)
    delete this;
}

void Socks4Server::Session::outgoing_event_cb(const short events) {
  if (events & BEV_EVENT_CONNECTED) {
    outgoing_valid_ = true;
    on_outgoing_connected();
  } else if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    const struct evbuffer* buf = ::bufferevent_get_output(incoming_);
    outgoing_valid_ = false;
    if (!incoming_valid_ || ::evbuffer_get_length(buf) == 0) {
      // Incoming is invalid or fully flushed, done!
      delete this;
    } else {
      // Need to attempt to flush incoming first
      ::bufferevent_disable(outgoing_, EV_READ);
      state_ = State::kFLUSHING_INCOMING;
    }
  }
}


bool Socks4Server::Session::outgoing_connect() {
  SL_ASSERT(outgoing_ == nullptr);
  SL_ASSERT(state_ == State::kREAD_REQUEST);

  outgoing_ = ::bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);
  if (outgoing_ == nullptr)
    return false;

  bufferevent_data_cb readcb = [](struct bufferevent *bev,
                                  void *ctx) {
    reinterpret_cast<Session*>(ctx)->outgoing_read_cb();
  };
  bufferevent_data_cb writecb = [](struct bufferevent *bev,
                                   void *ctx) {
    reinterpret_cast<Session*>(ctx)->outgoing_write_cb();
  };
  bufferevent_event_cb eventcb = [](struct bufferevent *bev,
                                    short events,
                                    void *ctx) {
    reinterpret_cast<Session*>(ctx)->outgoing_event_cb(events);
  };
  ::bufferevent_setcb(outgoing_, readcb, writecb, eventcb, this);
  ::bufferevent_enable(outgoing_, EV_READ | EV_WRITE);

  int ret = ::bufferevent_socket_connect(outgoing_, reinterpret_cast<struct
                                         sockaddr*>(&remote_addr_),
                                         sizeof(remote_addr_));
  state_ = State::kCONNECTING;
  return ret == 0;
}

} // namespace schwanenlied
