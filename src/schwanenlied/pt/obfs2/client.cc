/**
 * @file    obfs2/client.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   obfs2 (The Twobfuscator) Client (IMPLEMENTATION)
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


#include <algorithm>
#include <array>
#include <cstring>

#include <event2/buffer.h>

#include <openssl/rand.h>

#include "schwanenlied/pt/obfs2/client.h"

namespace schwanenlied {
namespace pt {
namespace obfs2 {

constexpr char Client::kLogger[];

void Client::on_outgoing_connected() {
  static constexpr ::std::array<uint8_t, 29> init_mac_key = { {
    'I', 'n', 'i', 't', 'i', 'a', 't', 'o', 'r', ' ',
    'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'i', 'o', 'n', ' ',
    'p', 'a', 'd', 'd', 'i', 'n', 'g'
  } };

  CLOG(INFO, kLogger) << "Starting obfs2 handshake "
                      << "(" << this << ": " << client_addr_str_ << " <-> "
                             << remote_addr_str_ << ")";

  // Derive INIT_SEED
  if (1 != ::RAND_bytes(&init_seed_[0], init_seed_.size())) {
    CLOG(ERROR, kLogger) << "Failed to derive INIT_SEED "
                         << "(" << this << ")";
out_error:
    send_socks5_response(Reply::kGENERAL_FAILURE);
    return;
  }

  /*
   * Derive INIT_PAD_KEY
   *
   * Note:
   * The obfs2 spec neglects to specify that the IV used here is also taken
   * from the MAC operation.
   */
  crypto::SecureBuffer init_pad_key(crypto::Sha256::kDigestLength, 0);
  if (!mac(init_mac_key.data(), init_mac_key.size(), init_seed_.data(),
           init_seed_.size(), init_pad_key)) {
    CLOG(ERROR, kLogger) << "Failed to derive INIT_PAD_KEY "
                         << "(" << this << ")";
    goto out_error;
  }
  if (!initiator_aes_.set_state(init_pad_key.substr(0, crypto::kAes128KeyLength),
                                nullptr, 0,
                                init_pad_key.data() + crypto::kAes128KeyLength,
                                init_pad_key.size() - crypto::kAes128KeyLength)) {
    CLOG(ERROR, kLogger) << "Failed to set INIT_PAD_KEY "
                         << "(" << this << ")";
    goto out_error;
  }

  /*
   * The spec says I send:
   *  * INIT_SEED
   *  * E(INIT_PAD_KEY, UINT32(MAGIC_VALUE) | UINT32(PADLEN) | WR(PADLEN))
   */

  // Generate the encrypted data
  const auto padlen = gen_padlen();
  ::std::array<uint32_t, 2> pad_hdr;
  constexpr size_t pad_hdr_sz = pad_hdr.size() * sizeof(uint32_t);
  pad_hdr.at(0) = htonl(kMagicValue);
  pad_hdr.at(1) = htonl(padlen);

  // Encrypt
  if (!initiator_aes_.process(reinterpret_cast<uint8_t*>(pad_hdr.data()),
                              pad_hdr_sz,
                              reinterpret_cast<uint8_t*>(pad_hdr.data()))) {
    CLOG(ERROR, kLogger) << "Failed to encrypt header "
                         << "(" << this << ")";
    goto out_error;
  }

  // Send INIT_SEED
  if (0 != ::bufferevent_write(outgoing_, init_seed_.data(), init_seed_.size())) {
    CLOG(ERROR, kLogger) << "Failed to send INIT_SEED "
                         << "(" << this << ")";
    goto out_error;
  }

  // Send the header
  if (0 != ::bufferevent_write(outgoing_, pad_hdr.data(), pad_hdr_sz)) {
    CLOG(ERROR, kLogger) << "Failed to send header "
                         << "(" << this << ")";
    goto out_error;
  }

  // Generate and send the random data
  if (padlen > 0) {
    uint8_t padding[kMaxPadding];
    ::evutil_secure_rng_get_bytes(padding, padlen);

    if (!initiator_aes_.process(padding, padlen, padding)) {
      CLOG(ERROR, kLogger) << "Failed to encrypt padding "
                           << "(" << this << ")";
      goto out_error;
    }

    if (0 != ::bufferevent_write(outgoing_, padding, padlen)) {
      CLOG(ERROR, kLogger) << "Failed to send padding "
                           << "(" << this << ")";
      goto out_error;
    }
  }

  CLOG(DEBUG, kLogger) << "Initiator obfs2 handshake complete "
                       << "(" << this << ": " <<client_addr_str_ << " <-> "
                              << remote_addr_str_ << ")";
}

void Client::on_incoming_data() {
  if (state_ != State::kESTABLISHED)
    return;

  // Pull data out of incoming_'s read buffer and AES-CTR
  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  uint8_t* p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
    CLOG(ERROR, kLogger) << "Failed to pullup buffer "
                         << "(" << this << ")";
out_error:
    delete this;
    return;
  }
  if (!initiator_aes_.process(p, len, p)) {
    CLOG(ERROR, kLogger) << "Failed to encrypt client payload "
                         << "(" << this << ")";
    goto out_error;
  }
  if (::bufferevent_write(outgoing_, p, len) != 0) {
    CLOG(ERROR, kLogger) << "Failed to send client payload "
                         << "(" << this << ")";
    goto out_error;
  }
  ::evbuffer_drain(buf, len);

  CLOG(DEBUG, kLogger) << "Sent " << len << " bytes to peer "
                       << "(" << this << ")";
}

void Client::on_outgoing_data_connecting() {
  SL_ASSERT(state_ == State::kCONNECTING);

  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);

  // Read the resp_seed, magic value and padlen
  if (!received_seed_hdr_) {
    static constexpr ::std::array<uint8_t, 29> resp_mac_key = { {
      'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r', ' ',
      'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'i', 'o', 'n', ' ',
      'p', 'a', 'd', 'd', 'i', 'n', 'g'
    } };
    const size_t len = ::evbuffer_get_length(buf);
    if (len < kSeedLength + sizeof(uint32_t) * 2)
      return;

    // Obtain RESP_SEED, and derive RESP_PAD_KEY
    if (static_cast<int>(kSeedLength) != ::evbuffer_remove(buf, &resp_seed_[0],
                                                           resp_seed_.size())) {
      CLOG(ERROR, kLogger) << "Failed to read RESP_SEED "
                           << "(" << this << ")";
out_error:
      send_socks5_response(Reply::kGENERAL_FAILURE);
      return;
    }
    crypto::SecureBuffer resp_pad_key(crypto::Sha256::kDigestLength, 0);
    if (!mac(resp_mac_key.data(), resp_mac_key.size(), resp_seed_.data(),
           resp_seed_.size(), resp_pad_key)) {
      CLOG(ERROR, kLogger) << "Failed to derive RESP_PAD_KEY "
                           << "(" << this << ")";
      goto out_error;
    }
    if (!responder_aes_.set_state(resp_pad_key.substr(0, crypto::kAes128KeyLength),
                                  nullptr, 0,
                                  resp_pad_key.data() + crypto::kAes128KeyLength,
                                  resp_pad_key.size() - crypto::kAes128KeyLength)) {
      CLOG(ERROR, kLogger) << "Failed to set RESP_PAD_KEY "
                           << "(" << this << ")";
      goto out_error;
    }

    // Validate the header and obtain padlen
    ::std::array<uint32_t, 2> pad_hdr;
    constexpr size_t pad_hdr_sz = pad_hdr.size() * sizeof(uint32_t);
    if (sizeof(uint32_t) * 2 != ::evbuffer_remove(buf, pad_hdr.data(), pad_hdr_sz))
        goto out_error;
    if (!responder_aes_.process(reinterpret_cast<uint8_t*>(pad_hdr.data()),
                                pad_hdr_sz,
                                reinterpret_cast<uint8_t*>(pad_hdr.data()))) {
      CLOG(ERROR, kLogger) << "Failed to decrypt header "
                           << "(" << this << ")";
      goto out_error;
    }
    if (ntohl(pad_hdr.at(0)) != kMagicValue) {
      CLOG(WARNING, kLogger) << "Received invalid magic value from peer "
                             << "(" << this << ")";
      goto out_error;
    }
    resp_pad_len_ = ntohl(pad_hdr.at(1));
    if (resp_pad_len_ > kMaxPadding) {
      CLOG(WARNING, kLogger) << "Peer claims to have sent too much padding: "
                             << resp_pad_len_ << " "
                             << "(" << this << ")";
      goto out_error;
    }

    // Derive the actual keys
    if (!kdf_obfs2()) {
      CLOG(ERROR, kLogger) << "Failed to derive session keys "
                           << "(" << this << ")";
      goto out_error;
    }

    received_seed_hdr_ = true;
  }

  // Skip the responder padding
  if (resp_pad_len_ > 0) {
    const size_t len = ::evbuffer_get_length(buf);
    const size_t to_drain = ::std::min(resp_pad_len_, len);
    ::evbuffer_drain(buf, to_drain);
    resp_pad_len_ -= to_drain;
    if (resp_pad_len_ > 0)
      return;
  }

  CLOG(INFO, kLogger) << "Finished obfs2 handshake "
                      << "(" << this << ": " << client_addr_str_ << " <-> "
                             << remote_addr_str_ << ")";

  // Handshaked
  send_socks5_response(Reply::kSUCCEDED);
}

void Client::on_outgoing_data() {
  if (state_ != State::kESTABLISHED)
    return;

  // Pull data out of outgoing_'s read buffer and AES-CTR
  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  uint8_t* p = ::evbuffer_pullup(buf, len);
  if (p == nullptr) {
    CLOG(ERROR, kLogger) << "Failed to pullup buffer "
                         << "(" << this << ")";
out_error:
    delete this;
    return;
  }
  if (!responder_aes_.process(p, len, p)) {
    CLOG(ERROR, kLogger) << "Failed to decrypt remote payload "
                         << "(" << this << ")";
    goto out_error;
  }
  if (::bufferevent_write(incoming_, p, len) != 0) {
    CLOG(ERROR, kLogger) << "Failed to send remote payload "
                         << "(" << this << ")";
    goto out_error;
  }
  ::evbuffer_drain(buf, len);

  CLOG(DEBUG, kLogger) << "Received " << len << " bytes from peer "
                       << "(" << this << ")";
}

bool Client::mac(const uint8_t* key,
                 const size_t key_len,
                 const uint8_t* buf,
                 const size_t len,
                 crypto::SecureBuffer& digest) {
  if (key == nullptr)
    return false;
  if (key_len == 0)
    return false;
  if (buf == nullptr)
    return false;
  if (len == 0)
    return false;
  if (digest.size() != crypto::Sha256::kDigestLength)
    return false;

  crypto::SecureBuffer to_sha(key_len *2 + len, 0);
  ::std::memcpy(&to_sha[0], key, key_len);
  ::std::memcpy(&to_sha[key_len], buf, len);
  ::std::memcpy(&to_sha[key_len + len], key, key_len);

  crypto::Sha256 sha;
  return sha.digest(to_sha.data(), to_sha.size(), &digest[0], digest.size());
}

bool Client::kdf_obfs2() {
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

  const crypto::SecureBuffer to_mac = init_seed_ + resp_seed_;
  crypto::SecureBuffer sekrit(crypto::Sha256::kDigestLength, 0);

  /*
   * INIT_SECRET = MAC("Initiator obfuscated data", INIT_SEED|RESP_SEED)
   * INIT_KEY = INIT_SECRET[:KEYLEN]
   * INIT_IV = INIT_SECRET[KEYLEN:]
   */
  if (!mac(init_data.data(), init_data.size(), to_mac.data(), to_mac.size(),
           sekrit))
    return false;
  if (!initiator_aes_.set_state(sekrit.substr(0, crypto::kAes128KeyLength),
                                nullptr, 0,
                                sekrit.data() + crypto::kAes128KeyLength,
                                sekrit.size() - crypto::kAes128KeyLength))
    return false;

  /*
   * RESP_SECRET = MAC("Responder obfuscated data", INIT_SEED|RESP_SEED)
   * RESP_KEY = RESP_SECRET[:KEYLEN]
   * RESP_IV = RESP_SECRET[KEYLEN:]
   */
  if (!mac(resp_data.data(), resp_data.size(), to_mac.data(), to_mac.size(),
           sekrit))
    return false;
  if (!responder_aes_.set_state(sekrit.substr(0, crypto::kAes128KeyLength),
                                nullptr, 0,
                                sekrit.data() + crypto::kAes128KeyLength,
                                sekrit.size() - crypto::kAes128KeyLength))
    return false;

  return true;
}

uint32_t Client::gen_padlen() const {
  uint32_t ret;

  // Sigh, why 8192 instead of 8192 - 1 :(
  do {
    ::evutil_secure_rng_get_bytes(&ret, sizeof(ret));
    ret &= 0x2fff;
  } while (ret > kMaxPadding);

  SL_ASSERT(ret < kMaxPadding);

  return ret;
}

} // namespace obfs2
} // namespace pt
} // namespace schwanenlied
