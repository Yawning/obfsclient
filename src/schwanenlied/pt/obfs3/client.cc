/**
 * @file    obfs3/client.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   obfs3 (The Threebfuscator) Client (IMPLEMENTATION)
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

#define OBFS3_CLIENT_IMPL

#include <array>

#include <event2/buffer.h>

#include "schwanenlied/pt/obfs3/client.h"

namespace schwanenlied {
namespace pt {
namespace obfs3 {

void Client::on_outgoing_connected() {
  SL_ASSERT(state_ == State::kCONNECTING);

  LOG(INFO) << this << ": Starting obfs3 handshake";

  // Send the public key
  const auto public_key = uniform_dh_.public_key();
  if (0 != ::bufferevent_write(outgoing_, public_key.data(),
                               public_key.size())) {
    LOG(ERROR) << this << ": Failed to send public key";
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  // Send the appropriate amount of random padding
  const auto padlen = pad_dist_(rand_);
  if (padlen > 0) {
    uint8_t padding[kMaxPadding / 2];
    if (!rand_.get_bytes(padding, padlen)) {
      LOG(ERROR) << this << ": Failed to generate padding";
      send_socks5_response(Reply::kGENERAL_FAILURE);
      return;
    }

    if (0 != ::bufferevent_write(outgoing_, padding, padlen)) {
      LOG(ERROR) << this << ": Failed to send key padding";
      send_socks5_response(Reply::kGENERAL_FAILURE);
      return;
    }
  }

  LOG(DEBUG) << this << ": Initiator obfs3 handshake complete";
}

void Client::on_incoming_data() {
  if (state_ != State::kESTABLISHED)
    return;
  
  if (!sent_magic_) {
    // Send random padding
    const auto padlen = pad_dist_(rand_);
    if (padlen > 0) {
      uint8_t padding[kMaxPadding / 2];
      if (!rand_.get_bytes(padding, padlen)) {
        LOG(ERROR) << this << ": Failed to generate post-key padding";
        send_socks5_response(Reply::kGENERAL_FAILURE);
        return;
      }
      if (0 != ::bufferevent_write(outgoing_, padding, padlen)) {
        LOG(ERROR) << this << ": Failed to send post-key padding";
        server_.close_session(this);
        return;
      }
    }

    // Send initiator_magic_
    if (0 != ::bufferevent_write(outgoing_, initiator_magic_.data(),
                                 initiator_magic_.size())) {
      LOG(ERROR) << this << ": Failed to send initiator magic";
      server_.close_session(this);
      return;
    }
    sent_magic_ = true;
  }

  // Pull data out of incoming_'s read buffer and AES-CTR
  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  uint8_t *p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
    LOG(ERROR) << this << ": Failed to pullup buffer";
    server_.close_session(this);
    return;
  }
  if (!initiator_aes_.process(p, len, p)) {
    LOG(ERROR) << this << ": Failed to encrypt client payload";
    server_.close_session(this);
    return;
  }
  if (::bufferevent_write(outgoing_, p, len) != 0) {
    LOG(ERROR) << this << ": Failed to send client payload";
    server_.close_session(this);
    return;
  }
  ::evbuffer_drain(buf, len);

  LOG(DEBUG) << this << ": Sent " << len << " bytes to peer";
}

void Client::on_outgoing_data_connecting() {
  SL_ASSERT(state_ == State::kCONNECTING);

  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);

  // Read the peer's public key
  const size_t len = ::evbuffer_get_length(buf);
  if (len < crypto::UniformDH::kKeyLength)
    return;

  const uint8_t *p = ::evbuffer_pullup(buf, crypto::UniformDH::kKeyLength);
  if (p == nullptr) {
    LOG(ERROR) << this << ": Failed to pullup public key";
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }
  if (!uniform_dh_.compute_key(p, crypto::UniformDH::kKeyLength)) {
    LOG(WARNING) << this << ": UniformDH key exchange failed";
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  // Apply the KDF and initialize the crypto
  if (!kdf_obfs3(uniform_dh_.shared_secret())) {
    LOG(ERROR) << this << ": Failed to derive session keys";
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }
  ::evbuffer_drain(buf, crypto::UniformDH::kKeyLength);

  LOG(INFO) << this << ": Finished obfs3 handshake";

  // Handshaked
  send_socks5_response(Reply::kSUCCEDED);
}

void Client::on_outgoing_data() {
  if (state_ != State::kESTABLISHED)
    return;

  if (!received_magic_) {
    struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
    const size_t len = ::evbuffer_get_length(buf);
    if (len < responder_magic_.size())
      return;

    auto found = ::evbuffer_search(buf, reinterpret_cast<const char*>(responder_magic_.data()),
                                   responder_magic_.size(), nullptr);
    if (found.pos > static_cast<ssize_t>(kMaxPadding)) {
      LOG(WARNING) << this << ": Peer sent too much padding: " << found.pos;
      server_.close_session(this);
      return;
    }
    if (found.pos == -1 && len > kMaxPadding + responder_magic_.size()) {
      LOG(WARNING) << this << ": Did not find mark within allowable limits";
      server_.close_session(this);
      return;
    }
    if (found.pos == -1)
      return;
    ::evbuffer_drain(buf, found.pos + responder_magic_.size());
    received_magic_ = true;
  }

  // Pull data out of outgoing_'s read buffer and AES-CTR
  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  uint8_t* p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
    LOG(ERROR) << this << ": Failed to pullup buffer";
    server_.close_session(this);
    return;
  }
  if (!responder_aes_.process(p, len, p)) {
    LOG(ERROR) << this << ": Failed to decrypt remote payload";
    server_.close_session(this);
    return;
  }
  if (::bufferevent_write(incoming_, p, len) != 0) {
    LOG(ERROR) << this << ": Failed to send remote payload";
    server_.close_session(this);
    return;
  }
  ::evbuffer_drain(buf, len);

  LOG(DEBUG) << this << ": Received " << len << " bytes from peer";
}

bool Client::kdf_obfs3(const crypto::SecureBuffer& shared_secret) {
  static constexpr ::std::array<uint8_t, 25> init_data = { {
    'I', 'n', 'i', 't', 'i', 'a', 't', 'o', 'r', ' ',
    'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'e', 'd', ' ',
    'd', 'a', 't', 'a'
  } };
  static constexpr ::std::array<uint8_t, 25> resp_data = { {
    'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r', ' ',
    'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'e', 'd', ' ',
    'd', 'a', 't', 'a'
  } };
  static constexpr ::std::array<uint8_t, 15> init_magic = { {
    'I', 'n', 'i', 't', 'i', 'a', 't', 'o', 'r', ' ',
    'm', 'a', 'g', 'i', 'c'
  } };
  static constexpr ::std::array<uint8_t, 15> resp_magic = { {
    'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r', ' ',
    'm', 'a', 'g', 'i', 'c'
  } };

  crypto::HmacSha256 hmac(shared_secret);
  crypto::SecureBuffer sekrit(crypto::HmacSha256::kDigestLength, 0);

  /*
   * INIT_SECRET = HMAC(SHARED_SECRET, "Initiator obfuscated data")
   * INIT_KEY = INIT_SECRET[:KEYLEN]
   * INIT_COUNTER = INIT_SECRET[KEYLEN:]
   */
  if (!hmac.digest(init_data.data(), init_data.size(), &sekrit[0],
                   sekrit.size()))
    return false;
  if (!initiator_aes_.set_state(sekrit.substr(0, crypto::kAes128KeyLength),
                                nullptr, 0,
                                sekrit.data() + crypto::kAes128KeyLength,
                                sekrit.size() - crypto::kAes128KeyLength))
    return false;

  /*
   * RESP_SECRET = HMAC(SHARED_SECRET, "Responder obfuscated data")
   * RESP_KEY = RESP_SECRET[:KEYLEN]
   * RESP_COUNTER = RESP_SECRET[KEYLEN:]
   */
  if (!hmac.digest(resp_data.data(), resp_data.size(), &sekrit[0],
                   sekrit.size()))
    return false;
  if (!responder_aes_.set_state(sekrit.substr(0, crypto::kAes128KeyLength),
                                nullptr, 0,
                                sekrit.data() + crypto::kAes128KeyLength,
                                sekrit.size() - crypto::kAes128KeyLength))
    return false;

  /*
   * HMAC(SHARED_SECRET, "Initiator magic")
   * HMAC(SHARED_SECRET, "Responder magic") 
   */
  if (!hmac.digest(init_magic.data(), init_magic.size(), &initiator_magic_[0],
                   initiator_magic_.size()))
    return false;
  if (!hmac.digest(resp_magic.data(), resp_magic.size(), &responder_magic_[0],
                   responder_magic_.size()))
    return false;

  return true;
}

} // namespace obfs3
} // namespace pt
} // namespace schwanenlied
