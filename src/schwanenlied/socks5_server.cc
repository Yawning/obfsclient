/**
 * @file    socks5_server.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SOCKSv5 Server (IMPLEMENTATION)
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

#include "schwanenlied/socks5_server.h"

namespace schwanenlied {

Socks5Server::~Socks5Server() {
  close();
}

const bool Socks5Server::addr(struct sockaddr_in& addr) const {
  if (listener_ == nullptr)
    return false;

  ::std::memcpy(&addr, &listener_addr_, sizeof(addr));

  return true;
}

bool Socks5Server::bind() {
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
    reinterpret_cast<Socks5Server*>(ptr)->on_new_connection(sock, addr, len);
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
  int ret = ::getsockname(sock, reinterpret_cast<struct sockaddr*>(&listener_addr_),
                           &len);
  if (ret != 0)
    return false;

  return true;
}

void Socks5Server::close() {
  if (listener_ != nullptr) {
    ::evconnlistener_free(listener_);
    listener_ = nullptr;
  }
}

void Socks5Server::on_new_connection(evutil_socket_t sock,
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

Socks5Server::Session::Session(struct event_base* base,
                               const evutil_socket_t sock,
                               const struct sockaddr* addr,
                               const int addr_len,
                               const bool require_auth) :
    base_(base),
    incoming_(nullptr),
    outgoing_(nullptr),
    remote_addr_(),
    remote_addr_len_(0),
    state_(State::kREAD_METHODS),
    auth_required_(require_auth),
    auth_method_(AuthMethod::kNO_ACCEPTABLE),
    incoming_valid_(false),
    outgoing_valid_(false) {
  incoming_ = ::bufferevent_socket_new(base_, sock, BEV_OPT_CLOSE_ON_FREE |
                                       BEV_OPT_DEFER_CALLBACKS);
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

Socks5Server::Session::~Session() {
  if (outgoing_ != nullptr)
    bufferevent_free(outgoing_);
  if (incoming_ != nullptr)
    bufferevent_free(incoming_);
}

void Socks5Server::Session::send_socks5_response(const Reply reply) {
  uint8_t resp[22] = { 0 };
  size_t resp_len = 0;

  /*
   * +----+-----+-------+------+----------+----------+
   * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
   * +----+-----+-------+------+----------+----------+
   * | 1  |  1  | X'00' |  1   | Variable |    2     |
   * +----+-----+-------+------+----------+----------+
   *
   * Since domain names are unsupported, BND.ADDR is either 4 or 16 bytes.
   */

  resp[0] = kSocksVersion;
  resp[1] = reply;

  if (reply == Reply::kSUCCEDED) {
    // Get the locally bound address
    struct sockaddr_storage addr;
    evutil_socket_t fd = bufferevent_getfd(outgoing_);
    socklen_t len = sizeof(addr);
    int ret = ::getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr),
                             &len);
    if (ret == 0) {
      switch (reinterpret_cast<struct sockaddr*>(&addr)->sa_family) {
      case AF_INET:
      {
        SL_ASSERT(len == sizeof(struct sockaddr_in));
        const struct sockaddr_in* v4addr = reinterpret_cast<struct sockaddr_in*>(&addr);
        resp_len = 10;
        resp[3] = AddressType::kIPv4;
        ::std::memcpy(resp + 4, &v4addr->sin_addr.s_addr, 4);
        ::std::memcpy(resp + 8, &v4addr->sin_port, 2);
        break;
      }
      case AF_INET6:
      {
        SL_ASSERT(len == sizeof(struct sockaddr_in6));
        const struct sockaddr_in6* v6addr = reinterpret_cast<struct sockaddr_in6*>(&addr);
        resp_len = 22;
        resp[3] = AddressType::kIPv6;
        ::std::memcpy(resp + 4, &v6addr->sin6_addr.s6_addr, 16);
        ::std::memcpy(resp + 20, &v6addr->sin6_port, 2);
        break;
      }
      default:
        resp[1] = Reply::kGENERAL_FAILURE;
        goto error_reply;
      }

      state_ = State::kESTABLISHED;
    } else {
      resp[1] = Reply::kGENERAL_FAILURE;
      goto error_reply;
    }
  } else {
error_reply:
    /* Just send a IPv4 address back on failure */
    resp_len = 10;
    resp[3] = AddressType::kIPv4;

    // Want to close as soon as the buffer is empty
    outgoing_valid_ = false;
    state_ = State::kFLUSHING_INCOMING;
  }

  int ret = ::bufferevent_write(incoming_, resp, resp_len);
  if (ret != 0)
    delete this;
  else if (state_ == State::kESTABLISHED)
    ::bufferevent_enable(incoming_, EV_READ);
}

void Socks5Server::Session::incoming_read_cb() {
  if (!incoming_valid_)
    return;

  switch (state_) {
  case State::kREAD_METHODS:
    incoming_read_methods_cb();
    break;
  case State::kAUTHENTICATING:
    incoming_read_auth_cb();
    break;
  case State::kREAD_REQUEST:
    incoming_read_request_cb();
    break;
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

void Socks5Server::Session::incoming_read_methods_cb() {
  SL_ASSERT(!outgoing_valid_);

  /*
   * +----+----------+----------+
   * |VER | NMETHODS | METHODS  |
   * +----+----------+----------+
   * | 1  |    1     | 1 to 255 |
   * +----+----------+----------+
   */

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len < 2)
    return;

  const uint8_t* p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
out_free:
    delete this;
    return;
  }

  if (p[0] != kSocksVersion)
    goto out_free;
  const uint8_t nmethods = p[1];
  if (len < static_cast<size_t>(2 + nmethods))
    return;

  bool can_none = false;
  bool can_username_password = false;
  bool can_tor_extended = false;

  for (int i = 0; i < nmethods; i++) {
    switch (p[2 + i]) {
    case AuthMethod::kNONE_REQUIRED:
      can_none = true;
      break;
    case AuthMethod::kUSERNAME_PASSWORD:
      can_username_password = true;
      break;
#if 0 // NOTYET - (https://trac.torproject.org/projects/tor/ticket/10671)
    case AuthMethod::kTOR_EXTENDED:
      can_tor_extended = true;
      break;
#endif
    }
  }

  if (auth_required_) {
    if (can_tor_extended)
      auth_method_ = AuthMethod::kTOR_EXTENDED;
    else if (can_username_password)
      auth_method_ = AuthMethod::kUSERNAME_PASSWORD;
  } else if (can_none)
    auth_method_ = AuthMethod::kNONE_REQUIRED;

  uint8_t method[2] = { kSocksVersion, auth_method_ };
  int ret = ::bufferevent_write(incoming_, method, sizeof(method));
  if (ret != 0)
    goto out_free;

  ::evbuffer_drain(buf, 2 + nmethods);
  switch (auth_method_) {
  case AuthMethod::kNONE_REQUIRED:
    state_ = State::kREAD_REQUEST;
    break;
  case AuthMethod::kUSERNAME_PASSWORD:
  case AuthMethod::kTOR_EXTENDED:
    state_ = State::kAUTHENTICATING;
    break;
  default:
    state_ = State::kFLUSHING_INCOMING;
  }
}

void Socks5Server::Session::incoming_read_auth_cb() {
  SL_ASSERT(auth_method_ != AuthMethod::kNONE_REQUIRED);
  SL_ASSERT(auth_method_ != AuthMethod::kNO_ACCEPTABLE);
  SL_ASSERT(auth_method_ == AuthMethod::kUSERNAME_PASSWORD);  // Remove later
  SL_ASSERT(!outgoing_valid_);

  /*
   * +----+------+----------+------+----------+
   * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
   * +----+------+----------+------+----------+
   * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
   * +----+------+----------+------+----------+
   */

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len < 2)
    return;

  const uint8_t* p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
out_fail:
    // Send a failure response
    const uint8_t resp[2] = { 0x01, 0xff };
    int ret = ::bufferevent_write(incoming_, resp, sizeof(resp));
    if (ret != 0) {
      delete this;
      return;
    }

    state_ = State::kFLUSHING_INCOMING;
    return;
  }

  // Version
  if (p[0] != 0x01)
    goto out_fail;

  // Username
  const uint8_t ulen = p[1];
  if (len < static_cast<size_t>(2 + ulen + 1))
    return;
  const uint8_t* uname = (ulen > 0) ? p + 2 : nullptr;

  // Password
  const uint8_t plen = p[2 + ulen];
  if (len < static_cast<size_t>(2 + ulen + 1 + plen))
    return;
  const uint8_t* passwd = (plen > 0) ? p + 2 + ulen + 1 : nullptr;

  /*
   * TODO: For the proposed TOR_EXTENDED auth, a uint16_t and extended data are
   * after passwd
   */

  if (on_client_authenticate(uname, ulen, passwd, plen)) {
    const uint8_t resp[2] = { 0x01, 0x00 };
      int ret = ::bufferevent_write(incoming_, resp, sizeof(resp));
    if (ret != 0) {
      delete this;
      return;
    }
    ::evbuffer_drain(buf, 2 + ulen + 1 + plen);
    state_ = State::kREAD_REQUEST;
  } else
    goto out_fail;
}

void Socks5Server::Session::incoming_read_request_cb() {
  SL_ASSERT(state_ == State::kREAD_REQUEST);
  SL_ASSERT(!outgoing_valid_);

  /*
   * +----+-----+-------+------+----------+----------+
   * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
   * +----+-----+-------+------+----------+----------+
   * | 1  |  1  | X'00' |  1   | Variable |    2     |
   * +----+-----+-------+------+----------+----------+
   */

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len < 4)
    return;

  size_t to_drain = 4;

  const uint8_t* p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  if (p[0] != kSocksVersion) {
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }
  if (p[1] != Command::kCONNECT) {
    send_socks5_response(Reply::kCOMMAND_NOT_SUPP);
    return;
  }
  if (p[2] != 0x00) {
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }
  if (p[3] == AddressType::kIPv4) {
    if (len < 10)
      return;

    struct sockaddr_in* v4addr = reinterpret_cast<struct sockaddr_in*>(&remote_addr_);
    remote_addr_len_ = sizeof(struct sockaddr_in);
    v4addr->sin_family = AF_INET;
    ::std::memcpy(&v4addr->sin_addr.s_addr, p + 4, 4);
    ::std::memcpy(&v4addr->sin_port, p + 4 + 4, 2);
    to_drain += 6;
  } else if (p[3] == AddressType::kIPv6) {
    if (len < 22)
      return;

    struct sockaddr_in6* v6addr = reinterpret_cast<struct sockaddr_in6*>(&remote_addr_);
    remote_addr_len_ = sizeof(struct sockaddr_in6);
    v6addr->sin6_family = AF_INET6;
    ::std::memcpy(&v6addr->sin6_addr.s6_addr, p + 4, 16);
    ::std::memcpy(&v6addr->sin6_port, p + 4 + 16, 2);
    to_drain += 18;
  } else {
    send_socks5_response(Reply::kADDR_NOT_SUPP);
    return;
  }

  // Connect
  ::evbuffer_drain(buf, to_drain);
  if (!outgoing_connect()) {
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  ::bufferevent_disable(incoming_, EV_READ);
}

void Socks5Server::Session::incoming_write_cb() {
  if (state_ == State::kESTABLISHED)
    on_incoming_drained();
  else if (state_ == State::kFLUSHING_INCOMING)
    delete this;
}

void Socks5Server::Session::incoming_event_cb(const short events) {
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    incoming_valid_ = false;
    const struct evbuffer* buf = ::bufferevent_get_output(outgoing_);
    if (!outgoing_valid_ || ::evbuffer_get_length(buf) == 0) {
      // Outgoing is invalid or fully flushed, done!
      delete this;
    } else {
      // Need to attempt to flush outgoing first
      ::bufferevent_disable(incoming_, EV_READ);
      ::bufferevent_setwatermark(outgoing_, EV_WRITE, 0, 0);
      state_ = State::kFLUSHING_OUTGOING;
    }
  }
}

void Socks5Server::Session::outgoing_read_cb() {
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

void Socks5Server::Session::outgoing_write_cb() {
  if (state_ == State::kCONNECTING || state_ == State::kESTABLISHED)
    on_outgoing_drained();
  else if (state_ == State::kFLUSHING_OUTGOING)
    delete this;
}

void Socks5Server::Session::outgoing_event_cb(const short events) {
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
      ::bufferevent_setwatermark(incoming_, EV_WRITE, 0, 0);
      state_ = State::kFLUSHING_INCOMING;
    }
  }
}


bool Socks5Server::Session::outgoing_connect() {
  SL_ASSERT(outgoing_ == nullptr);
  SL_ASSERT(state_ == State::kREAD_REQUEST);
  SL_ASSERT(remote_addr_len_ != 0);

  outgoing_ = ::bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE |
                                       BEV_OPT_DEFER_CALLBACKS);
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
                                         remote_addr_len_);
  state_ = State::kCONNECTING;
  return ret == 0;
}

} // namespace schwanenlied
