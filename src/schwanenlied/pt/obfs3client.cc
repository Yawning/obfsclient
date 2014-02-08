/**
 * @file    obfs3client.cc
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

#include <event2/event.h>
#include <event2/buffer.h>

#include "schwanenlied/pt/obfs3client.h"

namespace schwanenlied {
namespace pt {

void Obfs3Client::on_outgoing_connected() {
  SL_ASSERT(state_ == State::kCONNECTING);

  // Send the public key
  const auto public_key = uniform_dh_.public_key();
  int ret = ::bufferevent_write(outgoing_, public_key.data(),
                                public_key.size());
  if (ret != 0) {
out_error:
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  // Send the appropriate amount of random padding
  auto padlen = gen_padlen();
  if (padlen > 0) {
    uint8_t padding[kMaxPadding / 2];
    ::evutil_secure_rng_get_bytes(padding, padlen);

    ret = ::bufferevent_write(outgoing_, padding, padlen);
    if (ret != 0)
      goto out_error;
  }
}

void Obfs3Client::on_incoming_data() {
  if (state_ != State::kESTABLISHED)
    return;
  
  if (!sent_magic_) {
    // Send random padding
    auto padlen = gen_padlen();
    if (padlen > 0) {
      uint8_t padding[kMaxPadding / 2];
      ::evutil_secure_rng_get_bytes(padding, padlen);
      if (::bufferevent_write(outgoing_, padding, padlen) != 0) {
        delete this;
        return;
      }
    }

    // Send initiator_magic_
    if (::bufferevent_write(outgoing_, initiator_magic_.data(),
                            initiator_magic_.size()) != 0) {
      delete this;
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
    delete this;
    return;
  }
  if (!initiator_aes_.process(p, len, p)) {
    delete this;
    return;
  }
  if (::bufferevent_write(outgoing_, p, len) != 0) {
    delete this;
    return;
  }
  ::evbuffer_drain(buf, len);
}

void Obfs3Client::on_incoming_drained() {
  // Nothing to do yet
}

void Obfs3Client::on_outgoing_data_connecting() {
  SL_ASSERT(state_ == State::kCONNECTING);

  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);

  // Read the peer's public key
  size_t len = ::evbuffer_get_length(buf);
  if (len < crypto::UniformDH::kKeySz)
    return;

  uint8_t *p = ::evbuffer_pullup(buf, crypto::UniformDH::kKeySz);
  if (p == nullptr) {
out_error:
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }
  if (!uniform_dh_.compute_key(p, crypto::UniformDH::kKeySz))
    goto out_error;

  // Apply the KDF and initialize the crypto
  if (!kdf_obfs3(uniform_dh_.shared_secret()))
    goto out_error;

  ::evbuffer_drain(buf, crypto::UniformDH::kKeySz);

  // Handshaked
  send_socks5_response(Reply::kSUCCEDED);
}

void Obfs3Client::on_outgoing_data() {
  if (state_ != State::kESTABLISHED)
    return;

  if (!received_magic_) {
    struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
    size_t len = ::evbuffer_get_length(buf);
    if (len > kMaxPadding) {
      delete this;
      return;
    }

    auto found = ::evbuffer_search(buf, reinterpret_cast<const char*>(responder_magic_.data()),
                                   responder_magic_.size(), nullptr);
    if (found.pos == -1)
      return;
    if (found.pos > static_cast<ssize_t>(kMaxPadding + 1)) {
      delete this;
      return;
    }
    ::evbuffer_drain(buf, found.pos + responder_magic_.size());
    received_magic_ = true;
  }

  // Pull data out of outgoing_'s read buffer and AES-CTR
  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  uint8_t *p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
    delete this;
    return;
  }
  if (!responder_aes_.process(p, len, p)) {
    delete this;
    return;
  }
  if (::bufferevent_write(incoming_, p, len) != 0) {
    delete this;
    return;
  }
  ::evbuffer_drain(buf, len);
}

void Obfs3Client::on_outgoing_drained() {
  // Nothing to do yet
}

bool Obfs3Client::kdf_obfs3(const crypto::SecureBuffer& shared_secret) {
  const static uint8_t init_data[] = {
    'I', 'n', 'i', 't', 'i', 'a', 't', 'o', 'r', ' ',
    'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'e', 'd', ' ',
    'd', 'a', 't', 'a'
  };
  const static uint8_t resp_data[] = {
    'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r', ' ',
    'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'e', 'd', ' ',
    'd', 'a', 't', 'a'

  };
  const static uint8_t init_magic[] = {
    'I', 'n', 'i', 't', 'i', 'a', 't', 'o', 'r', ' ',
    'm', 'a', 'g', 'i', 'c'
  };
  const static uint8_t resp_magic[] = {
    'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r', ' ',
    'm', 'a', 'g', 'i', 'c'
  };

  crypto::HmacSha256 hmac(shared_secret);
  crypto::SecureBuffer sekrit(crypto::HmacSha256::kDigestLength, 0);

  /*
   * INIT_SECRET = HMAC(SHARED_SECRET, "Initiator obfuscated data")
   * INIT_KEY = INIT_SECRET[:KEYLEN]
   * INIT_COUNTER = INIT_SECRET[KEYLEN:]
   */
  if (!hmac.digest(init_data, sizeof(init_data), &sekrit[0], sekrit.size()))
    return false;
  if (!initiator_aes_.set_state(sekrit.substr(0, crypto::AesCtr128::kKeyLength),
                                sekrit.data() + crypto::AesCtr128::kKeyLength,
                                sekrit.size() - crypto::AesCtr128::kKeyLength))
    return false;

  /*
   * RESP_SECRET = HMAC(SHARED_SECRET, "Responder obfuscated data")
   * RESP_KEY = RESP_SECRET[:KEYLEN]
   * RESP_COUNTER = RESP_SECRET[KEYLEN:]
   */
  if (!hmac.digest(resp_data, sizeof(resp_data), &sekrit[0], sekrit.size()))
    return false;
  if (!responder_aes_.set_state(sekrit.substr(0, crypto::AesCtr128::kKeyLength),
                                sekrit.data() + crypto::AesCtr128::kKeyLength,
                                sekrit.size() - crypto::AesCtr128::kKeyLength))
    return false;

  /*
   * HMAC(SHARED_SECRET, "Initiator magic")
   * HMAC(SHARED_SECRET, "Responder magic") 
   */
  if (!hmac.digest(init_magic, sizeof(init_magic), &initiator_magic_[0],
                   initiator_magic_.size()))
    return false;
  if (!hmac.digest(resp_magic, sizeof(resp_magic), &responder_magic_[0],
                   responder_magic_.size()))
    return false;

  return true;
}

uint16_t Obfs3Client::gen_padlen() const {
  uint16_t ret;

  // Sigh, why 8194 instead of 8192 - 1 :(
  do {
    ::evutil_secure_rng_get_bytes(&ret, sizeof(ret));
    ret &= 0x2fff;
  } while (ret > kMaxPadding / 2);

  SL_ASSERT(ret <= kMaxPadding / 2);

  return ret;
}

} // namespace pt
} // namespace schwanenlied
