/**
 * @file    uniform_dh_handshake.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit UniformDH Handshake (IMPLEMENTATION)
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

#include <array>
#include <ctime>

#include <event2/buffer.h>

#include "schwanenlied/pt/scramblesuit/client.h"
#include "schwanenlied/pt/scramblesuit/uniform_dh_handshake.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

uint16_t UniformDHHandshake::gen_padlen() const {
  uint16_t ret;

  do {
    ::evutil_secure_rng_get_bytes(&ret, sizeof(ret));
    ret &= 0x5ff;
  } while (ret > kMaxPadding);

  SL_ASSERT(ret <= kMaxPadding);

  return ret;
}

bool UniformDHHandshake::send_handshake_msg(struct bufferevent* sink) {
  SL_ASSERT(sink != nullptr);

  /*
   * UniformDH handshake:
   * X | P_C | M_C | MAC(X | P_C | E)
   *
   * X -> UniformDH public key
   * P_C -> Padding [0 - 1308] bytes
   * M_C = HMAC-SHA256-128(k_B, X)
   * MAC = HMAC-SHA256-128(k_B, X | P_C | E)
   */

  if (!hmac_.init())
    return false;

  // Generate X
  const auto public_key = uniform_dh_.public_key();
  if (!hmac_.update(reinterpret_cast<const uint8_t*>(public_key.data()),
                    public_key.size()))
      return false;

  // Generate M_C
  ::std::array<uint8_t, kDigestLength> m_c;
  if (!hmac_.digest(reinterpret_cast<const uint8_t*>(public_key.data()),
                    public_key.size(), m_c.data(), m_c.size()))
    return false;

  // Generate P_C
  ::std::array<uint8_t, kMaxPadding> p_c;
  auto padlen = gen_padlen();
  if (padlen > 0) {
    ::evutil_secure_rng_get_bytes(p_c.data(), padlen);
    if (!hmac_.update(p_c.data(), padlen))
      return false;
  }

  // HACKHACKHACKHACKHACK
  if (!hmac_.update(m_c.data(), m_c.size()))
      return false;

  // Generate MAC
  epoch_hour_ = ::std::to_string(::std::time(nullptr) / 3600);
  if (!hmac_.update(reinterpret_cast<const uint8_t*>(epoch_hour_.data()),
                    epoch_hour_.size()))
    return false;
  ::std::array<uint8_t, kDigestLength> mac_c;
  if (!hmac_.final(mac_c.data(), mac_c.size()))
    return false;

  // Send the message out
  if (0 != ::bufferevent_write(sink, public_key.data(), public_key.size()))
    return false;
  if (padlen > 0)
    if (0 != ::bufferevent_write(sink, p_c.data(), padlen))
      return false;
  if (0 != ::bufferevent_write(sink, m_c.data(), m_c.size()))
    return false;
  if (0 != ::bufferevent_write(sink, mac_c.data(), mac_c.size()))
    return false;

  return true;
}

bool UniformDHHandshake::recv_handshake_msg(struct bufferevent* source,
                                            bool& is_finished) {
  struct evbuffer* buf = ::bufferevent_get_input(source);

  is_finished = false;

  /*
   * Y | P_S | M_S | MAC(Y | P_S | E) 
   *
   * Y -> UniformDH public key
   * P_S -> Padding [0 - 1308] bytes
   * M_S = HMAC-SHA256-128(k_B, Y)
   * MAC = HMAC-SHA256-128(k_B, Y | P_S | E)
   *
   * Note:
   * There is a network latency induced edge case here, as the current
   * ScrambleSuit server does not use the value of E used to verify 
   * the client's MAC when generating the server's MAC.  In theory, the
   * client could calculate MACs for E + 1/E - 1, but in my view, it's
   * preferable if the server deals with this.
   */
  
  if (remote_public_key_ == nullptr) {
    // Read Y
    size_t len = ::evbuffer_get_length(buf);
    if (len < kKeyLength)
      return true;

    if (!hmac_.init())
      return false;

    uint8_t* p = ::evbuffer_pullup(buf, kKeyLength);
    if (p == nullptr)
      return false;

    remote_public_key_ = ::std::unique_ptr<crypto::SecureBuffer>(
        new crypto::SecureBuffer(p, kKeyLength));

    uint8_t digest[kDigestLength];
    if (!hmac_.update(p, kKeyLength))
      return false;
    if (!hmac_.digest(p, kKeyLength, digest, sizeof(digest)))
      return false;

    remote_mark_ = ::std::unique_ptr<crypto::SecureBuffer>(
        new crypto::SecureBuffer(digest, sizeof(digest)));

    ::evbuffer_drain(buf, kKeyLength);
  }

  SL_ASSERT(remote_public_key_ != nullptr);
  SL_ASSERT(remote_mark_ != nullptr);

  if (remote_mac_ == nullptr) {
    // Attempt to find M_S
    size_t len = ::evbuffer_get_length(buf);
    if (len < remote_mark_->size())
      return true;

    auto found = ::evbuffer_search(buf, reinterpret_cast<const char*>(remote_mark_->data()),
                                   remote_mark_->size(), nullptr);
    if (found.pos == -1)
      return true;
    if (found.pos > static_cast<ssize_t>(kMaxPadding + 1))
      return false;

    // MAC the padding if any
    if (found.pos > 0) {
      // HACKHACKHACKHACK
      const size_t to_mac = found.pos + remote_mark_->size();
      uint8_t* p = ::evbuffer_pullup(buf, to_mac);
      if (p == nullptr)
        return false;
      if (!hmac_.update(p, to_mac))
        return false;
    }

    // MAC the epoch hour
    if (!hmac_.update(reinterpret_cast<const uint8_t*>(epoch_hour_.data()),
                      epoch_hour_.size()))
      return false;

    // Calculate the expected MAC_S
    uint8_t digest[kDigestLength];
    if (!hmac_.final(digest, sizeof(digest)))
      return false;

    remote_mac_ = ::std::unique_ptr<crypto::SecureBuffer>(
        new crypto::SecureBuffer(digest, sizeof(digest)));

    ::evbuffer_drain(buf, found.pos + remote_mark_->size());
  }

  SL_ASSERT(remote_mac_ != nullptr);

  // Extract M_S, and compare it to what was calculated
  size_t len = ::evbuffer_get_length(buf);
  if (len < remote_mac_->size())
    return true;

  uint8_t* p = ::evbuffer_pullup(buf, remote_mac_->size());
  if (p == nullptr)
    return false;

  if (!crypto::memequals(remote_mac_->data(), p, remote_mac_->size()))
    return false;

  ::evbuffer_drain(buf, remote_mac_->size());

  // Actually do the Diffie-Hellman handshake
  if (!uniform_dh_.compute_key(remote_public_key_->data(),
                               remote_public_key_->size()))
    return false;

  // Derive k_t
  crypto::Sha256 sha;
  const auto sekrit = uniform_dh_.shared_secret();
  if (!sha.digest(sekrit.data(), sekrit.size(), &shared_secret_[0],
                  shared_secret_.size()))
    return false;

  // The the the that's all folks!
  is_finished = true;
  has_shared_secret_ = true;

  return true;
}

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenelied
