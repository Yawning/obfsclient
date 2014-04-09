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

#define SOCKS5_SERVER_IMPL

#include <cstring>
#include <random>

#include <event2/buffer.h>

#include "schwanenlied/socks5_server.h"
#include "schwanenlied/crypto/rand_openssl.h"

namespace schwanenlied {

Socks5Server::~Socks5Server() {
  close();
  close_sessions();
}

bool Socks5Server::addr(struct sockaddr_in& addr) const {
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
  listener_addr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  // Initialize the on connect callback, shamelessly abusing a lambda
  evconnlistener_cb cb = [](struct evconnlistener* listener,
                            evutil_socket_t sock,
                            struct sockaddr* addr,
                            int len,
                            void* ptr) {
    (void)listener;

    reinterpret_cast<Socks5Server*>(ptr)->on_new_connection(sock, addr, len);
  };

  listener_ = ::evconnlistener_new_bind(base_, cb, this,
                                        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                        -1, reinterpret_cast<struct sockaddr*>(&listener_addr_),
                                        sizeof(listener_addr_));
  if (listener_ == nullptr) {
    LOG(ERROR) << this << ": Failed to create an evconnlistener";
    return false;
  }

  // Query the port that end up bound
  const evutil_socket_t sock = ::evconnlistener_get_fd(listener_);
  socklen_t len = sizeof(listener_addr_);
  int ret = ::getsockname(sock, reinterpret_cast<struct sockaddr*>(&listener_addr_),
                           &len);
  if (ret != 0) {
    PLOG(ERROR) << this << ": Failed to getsockname() listener";
    return false;
  }

  listener_addr_str_ = addr_to_string(reinterpret_cast<const struct sockaddr*>(&listener_addr_),
                                      false);

  return true;
}

void Socks5Server::close() {
  if (listener_ != nullptr) {
    LOG(INFO) << this << ": Closing listener " << listener_addr_str_;

    ::evconnlistener_free(listener_);
    listener_ = nullptr;
  }
}

void Socks5Server::close_session(Session* session) {
  for (auto iter = sessions_.begin(); iter != sessions_.end(); ++iter) {
    if ((*iter).get() == session) {
      iter = sessions_.erase(iter);
      return;
    }
  }
}

void Socks5Server::close_sessions() {
  if (sessions_.size() > 0) {
    LOG(INFO) << this << ": Force closing sessions";
    for (auto iter = sessions_.begin(); iter != sessions_.end(); ++iter) {
      (*iter).reset(nullptr);
    }
    sessions_.clear();
  }
}

void Socks5Server::on_new_connection(evutil_socket_t sock,
                                     struct sockaddr* addr,
                                     int addr_len) {
  (void)addr_len;

  // Don't bother scrubbing the client address (loopback)
  ::std::string client_addr = addr_to_string(addr, false);

  Session* session = factory_->create_session(*this, base_, sock, client_addr,
                                              scrub_addrs_);
  if (session == nullptr) {
    evutil_closesocket(sock);
  } else {
    LOG(INFO) << session << ": New client connection "
              << client_addr << " -> " << listener_addr_str_;
    sessions_.push_back(::std::unique_ptr<Session>(session));
  }
}

Socks5Server::Session::Session(Socks5Server& server,
                               struct event_base* base,
                               const evutil_socket_t sock,
                               const ::std::string& client_addr,
                               const bool require_auth,
                               const bool scrub_addrs) :
    server_(server),
    base_(base),
    incoming_(nullptr),
    outgoing_(nullptr),
    remote_addr_(),
    remote_addr_len_(0),
    state_(State::kREAD_METHODS),
    client_addr_str_(client_addr),
    remote_addr_str_("[Not yet specified]"),
    auth_required_(require_auth),
    scrub_addrs_(scrub_addrs),
    auth_method_(AuthMethod::kNO_ACCEPTABLE),
    incoming_valid_(false),
    outgoing_valid_(false),
    connect_timer_ev_(nullptr) {
  incoming_ = ::bufferevent_socket_new(base_, sock, BEV_OPT_CLOSE_ON_FREE |
                                       BEV_OPT_DEFER_CALLBACKS);
  CHECK_NOTNULL(incoming_);

  // Initialize the callbacks for the incoming socket
  bufferevent_data_cb readcb = [](struct bufferevent *bev,
                                  void *ctx) {
    (void)bev;

    reinterpret_cast<Session*>(ctx)->incoming_read_cb();
  };
  bufferevent_data_cb writecb = [](struct bufferevent *bev,
                                   void *ctx) {
    (void)bev;

    reinterpret_cast<Session*>(ctx)->incoming_write_cb();
  };
  bufferevent_event_cb eventcb = [](struct bufferevent *bev,
                                    short events,
                                    void *ctx) {
    (void)bev;

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
  if (connect_timer_ev_ != nullptr)
    ::event_free(connect_timer_ev_);
}

bool Socks5Server::Session::send_socks5_response(const Reply reply) {
  uint8_t resp[22] = { 0 };
  size_t resp_len = 0;

  // Disarm the timer
  if (connect_timer_ev_ != nullptr)
    if (evtimer_pending(connect_timer_ev_, nullptr))
      evtimer_del(connect_timer_ev_);

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
        CHECK_EQ(len, sizeof(struct sockaddr_in)) << this
            << ": send_socks5_response(): Invalid IPv4 addr length: " << len;
        const struct sockaddr_in* v4addr = reinterpret_cast<struct sockaddr_in*>(&addr);
        resp_len = 10;
        resp[3] = AddressType::kIPv4;
        ::std::memcpy(resp + 4, &v4addr->sin_addr.s_addr, 4);
        ::std::memcpy(resp + 8, &v4addr->sin_port, 2);
        break;
      }
      case AF_INET6:
      {
        CHECK_EQ(len, sizeof(struct sockaddr_in6)) << this
            << ": send_socks5_response(): Invalid IPv6 addr length: " << len;
        const struct sockaddr_in6* v6addr = reinterpret_cast<struct sockaddr_in6*>(&addr);
        resp_len = 22;
        resp[3] = AddressType::kIPv6;
        ::std::memcpy(resp + 4, &v6addr->sin6_addr.s6_addr, 16);
        ::std::memcpy(resp + 20, &v6addr->sin6_port, 2);
        break;
      }
      default:
        // This should never happen
        LOG(ERROR) << this << ": getsockname() returned a invalid address, closing";
        return send_socks5_response(Reply::kGENERAL_FAILURE);
      }

      state_ = State::kESTABLISHED;
    } else {
      PLOG(ERROR) << "Failed to getsockname() outgoing";
      return send_socks5_response(Reply::kGENERAL_FAILURE);
    }
  } else {
    /* Just send a IPv4 address back on failure */
    resp_len = 10;
    resp[3] = AddressType::kIPv4;

    LOG(DEBUG) << this << ": Sending SOCKS error: " << static_cast<int>(resp[1]);

    // Want to close as soon as the buffer is empty
    outgoing_valid_ = false;
    state_ = State::kFLUSHING_INCOMING;
  }

  if (0 != ::bufferevent_write(incoming_, resp, resp_len)) {
    LOG(ERROR) << this << ": Failed to write SOCKS response, closing";
    server_.close_session(this);
    return false;
  } else if (state_ == State::kESTABLISHED) {
    ::bufferevent_enable(incoming_, EV_READ);
    LOG(INFO) << this << ": Connection setup complete "
              << client_addr_str_ << " <-> " << remote_addr_str_;
    return true;
  }

  return false;
}

const char* Socks5Server::Session::state_string() const {
  switch (state_) {
  case State::kINVALID: return "kINVALID";
  case State::kREAD_METHODS: return "kREAD_METHODS";
  case State::kAUTHENTICATING: return "kAUTHENTICATING";
  case State::kREAD_REQUEST: return "kREAD_REQUEST";
  case State::kCONNECTING: return "kCONNECTING";
  case State::kESTABLISHED: return "kESTABLISHED";
  case State::kFLUSHING_INCOMING: return "kFLUSHING_INCOMING";
  case State::kFLUSHING_OUTGOING: return "kFLUSHING_OUTGOING";
  }

  /* Should *NEVER* happen */
  LOG(FATAL) << "state_string(): Unknown state";
  return nullptr; /* NOTREACHED */
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
    if (on_incoming_data())
      incoming_apply_backpressure();
    break;
  default:
    LOG(FATAL) << this << ": incoming_read_cb() Invalid state: " << state_string();
  }
}

void Socks5Server::Session::incoming_read_methods_cb() {
  CHECK(!outgoing_valid_) << this
      << ":incoming_read_methods_cb(): Expected outgoing_ to be invalid";

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
    LOG(ERROR) << this << ": Failed to pullup buffer";
    server_.close_session(this);
    return;
  }

  if (p[0] != kSocksVersion) {
    LOG(WARNING) << this << ": Invalid SOCKS protocol version: " << p[0];
    server_.close_session(this);
    return;
  }
  const uint8_t nmethods = p[1];
  if (len < static_cast<size_t>(2 + nmethods))
    return;

  bool can_none = false;
  bool can_username_password = false;

  for (int i = 0; i < nmethods; i++) {
    switch (p[2 + i]) {
    case AuthMethod::kNONE_REQUIRED:
      can_none = true;
      break;
    case AuthMethod::kUSERNAME_PASSWORD:
      can_username_password = true;
      break;
    }
  }

  if (auth_required_) {
    if (can_username_password)
      auth_method_ = AuthMethod::kUSERNAME_PASSWORD;
    else {
      LOG(WARNING) << this << ": Failed to negotiate compatible auth";
      server_.close_session(this);
      return;
    }
  } else if (can_none)
    auth_method_ = AuthMethod::kNONE_REQUIRED;

  LOG(DEBUG) << this << ": Negotiated auth method: " << auth_method_;

  uint8_t method[2] = { kSocksVersion, static_cast<uint8_t>(auth_method_) };
  if (0 != ::bufferevent_write(incoming_, method, sizeof(method))) {
    LOG(ERROR) << this << ": Failed to write auth method, closing";
    server_.close_session(this);
    return;
  }

  ::evbuffer_drain(buf, 2 + nmethods);
  switch (auth_method_) {
  case AuthMethod::kNONE_REQUIRED:
    state_ = State::kREAD_REQUEST;
    break;
  case AuthMethod::kUSERNAME_PASSWORD:
    state_ = State::kAUTHENTICATING;
    break;
  default:
    LOG(WARNING) << this << ": No suitable auth methods, closing";
    state_ = State::kFLUSHING_INCOMING;
  }
}

void Socks5Server::Session::incoming_read_auth_cb() {
  CHECK_EQ(auth_method_, AuthMethod::kUSERNAME_PASSWORD) << this
      << ": incoming_read_auth_cb(): Invalid auth method: " << auth_method_;
  CHECK(!outgoing_valid_) << this
      << ": incoming_read_auth_cb(): Expected outgoing_ to be invalid";

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
    LOG(ERROR) << this << ": Failed to pullup buffer";
out_fail:
    // Send a failure response
    const uint8_t resp[2] = { 0x01, 0xff };
    if (0 != ::bufferevent_write(incoming_, resp, sizeof(resp))) {
      LOG(ERROR) << this << ": Failed to write auth response, closing";
      server_.close_session(this);
      return;
    }

    state_ = State::kFLUSHING_INCOMING;
    return;
  }

  // Version
  if (p[0] != 0x01) {
    LOG(WARNING) << this << ": Invalid SOCKS auth version: " << p[0];
    goto out_fail;
  }

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

  if (!on_client_authenticate(uname, ulen, passwd, plen)) {
    LOG(WARNING) << this << ": Authentication failed, closing";
    goto out_fail;
  }

  LOG(DEBUG) << this << ": Authenticated";

  const uint8_t resp[2] = { 0x01, 0x00 };
  if (0 != ::bufferevent_write(incoming_, resp, sizeof(resp))) {
    LOG(ERROR) << this << ": Failed to write auth response, closing";
    server_.close_session(this);
    return;
  }
  ::evbuffer_drain(buf, 2 + ulen + 1 + plen);
  state_ = State::kREAD_REQUEST;
}

void Socks5Server::Session::incoming_read_request_cb() {
  CHECK_EQ(state_, State::kREAD_REQUEST) << this
      << ": incoming_read_request_cb(): Invalid state: " << state_string();
  CHECK(!outgoing_valid_) << this
      << ": incoming_read_request_cb(): Expected outgoing_ to be invalid";

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
    LOG(ERROR) << this << ": Failed to pullup buffer";
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  if (p[0] != kSocksVersion) {
    LOG(WARNING) << this << ": Invalid SOCKS protocol version: " << p[0];
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }
  if (p[1] != Command::kCONNECT) {
    LOG(WARNING) << this << ": Invalid SOCKS command: " << p[1];
    send_socks5_response(Reply::kCOMMAND_NOT_SUPP);
    return;
  }
  if (p[2] != 0x00) {
    LOG(WARNING) << this << ": Invalid SOCKS reserved field: " << p[2];
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
    LOG(WARNING) << this << ": Invalid SOCKS address type: " << p[3];
    send_socks5_response(Reply::kADDR_NOT_SUPP);
    return;
  }

  remote_addr_str_ = addr_to_string(reinterpret_cast<struct sockaddr*>(&remote_addr_),
                                scrub_addrs_);

  LOG(INFO) << this << ": Connecting to peer "
            << client_addr_str_ << " <-> " << remote_addr_str_;

  // Connect
  ::evbuffer_drain(buf, to_drain);
  if (!outgoing_connect()) {
    LOG(ERROR) << this << ": Failed to start connecting, closing";
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  ::bufferevent_disable(incoming_, EV_READ);
  if (outgoing_ != nullptr)
    ::bufferevent_disable(outgoing_, EV_READ);
}

void Socks5Server::Session::connect_timeout_cb() {
  CHECK_EQ(state_, State::kCONNECTING) << this
      << ": connect_timeout_cb(): Invalid state: " << state_string();

  LOG(WARNING) << this << ": Session handshake timeout";
  on_connect_timeout();
}

void Socks5Server::Session::incoming_write_cb() {
  if (state_ == State::kESTABLISHED)
    incoming_apply_backpressure();
  else if (state_ == State::kFLUSHING_INCOMING) {
    LOG(INFO) << this << ": Session closed";
    server_.close_session(this);
    return;
  }
}

void Socks5Server::Session::incoming_event_cb(const short events) {
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    incoming_valid_ = false;
    const struct evbuffer* buf = ::bufferevent_get_output(outgoing_);
    if (!outgoing_valid_ || (::evbuffer_get_length(buf) == 0 &&
                             !on_outgoing_flush())) {
      // Outgoing is invalid or fully flushed, done!
      LOG(INFO) << this << ": Session closed";
      server_.close_session(this);
      return;
    } else {
      // Need to attempt to flush outgoing first
      LOG(DEBUG) << this << ": Local connection closed, flushing remote";
      ::bufferevent_disable(incoming_, EV_READ);
      ::bufferevent_disable(outgoing_, EV_READ);
      ::bufferevent_setwatermark(outgoing_, EV_WRITE, 0, 0);
      state_ = State::kFLUSHING_OUTGOING;
    }
  }
}

void Socks5Server::Session::outgoing_connect_cb(const short events) {
  CHECK_EQ(state_, State::kCONNECTING) << this
      << ": outgoing_connect_cb(): Invalid state: " << state_string();

  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    const auto err = EVUTIL_SOCKET_ERROR();
    switch (err) {
    case ENETUNREACH:
      LOG(WARNING) << this << ": Peer network unreachable "
                   << client_addr_str_ << " <-> " << remote_addr_str_;
      send_socks5_response(Reply::kNETWORK_UNREACHABLE);
      break;
    case EHOSTUNREACH:
      LOG(WARNING) << this << ": Peer host unreachable "
                             << client_addr_str_ << " <-> " << remote_addr_str_;
      send_socks5_response(Reply::kHOST_UNREACHABLE);
      break;
    case ECONNREFUSED:
      LOG(WARNING) << this << ": Peer refused connection "
                   << client_addr_str_ << " <-> " << remote_addr_str_;
      send_socks5_response(Reply::kCONNECTION_REFUSED);
      break;
    case ETIMEDOUT:
      LOG(WARNING) << this << ": Peer connection timedout "
                   << client_addr_str_ << " <-> " << remote_addr_str_;
      send_socks5_response(Reply::kTTL_EXPIRED);
      break;
    default:
      LOG(WARNING) << this << ": Peer connection failed: " << err << " "
                   << client_addr_str_ << " <-> " << remote_addr_str_;
      send_socks5_response(Reply::kGENERAL_FAILURE);
    }

    // Flush the reply
    outgoing_event_cb(events);
  } else if (events & BEV_EVENT_CONNECTED) {
    // Initialize the handshake timeout
    event_callback_fn timeoutcb = [](evutil_socket_t sock,
                                     short which,
                                     void* arg) {
      (void)sock;
      (void)which;

      reinterpret_cast<Session*>(arg)->connect_timeout_cb();
    };
    SL_ASSERT(connect_timer_ev_ == nullptr);
    connect_timer_ev_ = evtimer_new(base_, timeoutcb, this);
    if (connect_timer_ev_ == nullptr) {
      LOG(ERROR) << this << ": Failed to allocate timeout timer, closing";
      send_socks5_response(Reply::kGENERAL_FAILURE);
      return;
    }

    // Arm the handshake timeout
    crypto::RandOpenSSL rand;
    ::std::uniform_int_distribution<uint32_t> alpha(0, kConnectTimeout);
    struct timeval tv;
    tv.tv_sec = kConnectTimeout + alpha(rand);
    tv.tv_usec = 0;
    evtimer_add(connect_timer_ev_, &tv);
    LOG(INFO) << this << ": Randomizing connect timeout: " << tv.tv_sec << " sec";

    // Setup the bufferevents
    bufferevent_data_cb readcb = [](struct bufferevent* bev,
                                    void* ctx) {
      (void)bev;

      reinterpret_cast<Session*>(ctx)->outgoing_read_cb();
    };
    bufferevent_data_cb writecb = [](struct bufferevent* bev,
                                     void* ctx) {
      (void)bev;

      reinterpret_cast<Session*>(ctx)->outgoing_write_cb();
    };
    bufferevent_event_cb eventcb = [](struct bufferevent* bev,
                                      short events,
                                      void* ctx) {
      (void)bev;

      reinterpret_cast<Session*>(ctx)->outgoing_event_cb(events);
    };
    ::bufferevent_enable(outgoing_, EV_READ | EV_WRITE);
    ::bufferevent_setcb(outgoing_, readcb, writecb, eventcb, this);

    LOG(DEBUG) << this << ": Connected "
               << client_addr_str_ << " <-> " << remote_addr_str_;

    outgoing_valid_ = true;
    on_outgoing_connected();
    return;
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
    if (on_outgoing_data())
      outgoing_apply_backpressure();
    break;
  default:
    LOG(FATAL) << this << ": outgoing_read_cb() Invalid state: " << state_string();
  }
}

void Socks5Server::Session::outgoing_write_cb() {
  if (state_ == State::kCONNECTING || state_ == State::kESTABLISHED)
    outgoing_apply_backpressure();
  else if (state_ == State::kFLUSHING_OUTGOING && on_outgoing_flush()) {
    LOG(INFO) << this << ": Session closed";
    server_.close_session(this);
    return;
  }
}

void Socks5Server::Session::outgoing_event_cb(const short events) {
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    const struct evbuffer* buf = ::bufferevent_get_output(incoming_);
    outgoing_valid_ = false;
    if (!incoming_valid_ || ::evbuffer_get_length(buf) == 0) {
      // Incoming is invalid or fully flushed, done!
      LOG(INFO) << this << ": Session closed";
      server_.close_session(this);
      return;
    } else {
      // Need to attempt to flush incoming first
      LOG(DEBUG) << this << ": Remote connection closed, flushing local";
      ::bufferevent_disable(incoming_, EV_READ);
      ::bufferevent_disable(outgoing_, EV_READ);
      ::bufferevent_setwatermark(incoming_, EV_WRITE, 0, 0);
      state_ = State::kFLUSHING_INCOMING;
    }
  }
}

bool Socks5Server::Session::outgoing_connect() {
  CHECK_EQ(outgoing_, nullptr) << this
      << ": outgoing_connect(): Expected outgoing_ to be null";
  CHECK_EQ(state_, State::kREAD_REQUEST) << this
      << ": outgoing_connect(): Invalid state: " << state_string();
  CHECK_GT(remote_addr_len_, 0) << this
      << ": outgoing_connect(): Expected remote_addr_len to be > 0: "
      << remote_addr_len_;

  outgoing_ = ::bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE |
                                       BEV_OPT_DEFER_CALLBACKS);
  if (outgoing_ == nullptr)
    return false;

  bufferevent_event_cb eventcb = [](struct bufferevent *bev,
                                    short events,
                                    void *ctx) {
    (void)bev;

    reinterpret_cast<Session*>(ctx)->outgoing_connect_cb(events);
  };
  ::bufferevent_setcb(outgoing_, nullptr, nullptr, eventcb, this);

  // Return value is ignored since the callback will get invoked
  ::bufferevent_socket_connect(outgoing_,
                               reinterpret_cast<struct sockaddr*>(&remote_addr_),
                               remote_addr_len_);

  state_ = State::kCONNECTING;
  return true;
}

void Socks5Server::Session::incoming_apply_backpressure() {
  if (state_ != State::kESTABLISHED || !incoming_valid_ || !outgoing_valid_)
    return;

  const struct evbuffer* inc_buf = ::bufferevent_get_input(incoming_);
  const size_t inc_len = ::evbuffer_get_length(inc_buf);

  const struct evbuffer* out_buf = ::bufferevent_get_output(outgoing_);
  const size_t out_len = ::evbuffer_get_length(out_buf);

  LOG(DEBUG) << this << ": Outgoing write buffer: " << out_len;

  if (out_len > kMaxBufferSize) {
    if (0 != (::bufferevent_get_enabled(incoming_) & EV_READ)) {
      LOG(DEBUG) << this << ": Throttling incoming->outgoing";
      ::bufferevent_disable(incoming_, EV_READ);
      ::bufferevent_setwatermark(outgoing_, EV_WRITE, kMaxBufferSize / 2, 0);
    }
  } else {
    if (0 == (::bufferevent_get_enabled(incoming_) & EV_READ)) {
      LOG(DEBUG) << this << ": Unthrottling incoming->outgoing";
      ::bufferevent_enable(incoming_, EV_READ);
      ::bufferevent_setwatermark(outgoing_, EV_WRITE, 0, 0);
      if (inc_len > 0)
        on_incoming_data();
    }
  }
}

void Socks5Server::Session::outgoing_apply_backpressure() {
  if (state_ != State::kESTABLISHED || !incoming_valid_ || !outgoing_valid_)
    return;

  const struct evbuffer* out_buf = ::bufferevent_get_input(outgoing_);
  const size_t out_len = ::evbuffer_get_length(out_buf);

  const struct evbuffer* inc_buf = ::bufferevent_get_output(incoming_);
  const size_t inc_len = ::evbuffer_get_length(inc_buf);

  LOG(DEBUG) << this << ": Incoming write buffer: " << inc_len;

  if (inc_len > kMaxBufferSize) {
    if (0 != (::bufferevent_get_enabled(outgoing_) & EV_READ)) {
      LOG(DEBUG) << this << ": Throttling outging->incoming";
      ::bufferevent_disable(outgoing_, EV_READ);
      ::bufferevent_setwatermark(incoming_, EV_WRITE, kMaxBufferSize / 2, 0);
    }
  } else {
    if (0 == (::bufferevent_get_enabled(outgoing_) & EV_READ)) {
      LOG(DEBUG) << this << ": Unthrottling outgoing->incoming";
      ::bufferevent_enable(outgoing_, EV_READ);
      ::bufferevent_setwatermark(incoming_, EV_WRITE, 0, 0);
      if (out_len > 0)
        on_outgoing_data();
    }
  }
}

} // namespace schwanenlied
