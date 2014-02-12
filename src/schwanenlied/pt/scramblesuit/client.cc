/**
 * @file    scramblesuit/client.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit Client (IMPLEMENTATION)
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
#include <algorithm>
#include <cstring>
#include <string>

#include <event2/buffer.h>

#include "schwanenlied/crypto/base32.h"
#include "schwanenlied/crypto/hkdf_sha256.h"
#include "schwanenlied/pt/scramblesuit/client.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

const size_t Client::kMaxPayloadLength;

bool Client::on_client_authenticate(const uint8_t* uname,
                                    const uint8_t ulen,
                                    const uint8_t* passwd,
                                    const uint8_t plen) {
  static const ::std::string passwd_prefix("password=");
  static const size_t passwd_len_base32 = 32;
  if ((uint16_t)ulen + plen == 0)
    return false;

  ::std::string args((size_t)ulen + plen, 0);
  if (uname != nullptr)
    ::std::memcpy(&args[0], uname, ulen);
  if (passwd != nullptr)
    ::std::memcpy(&args[ulen], passwd, plen);

  // One day I will write a CSV parser
  size_t pos = args.find(passwd_prefix);
  if (pos != 0) {
burn:
    crypto::memwipe(&args[0], args.size());
    return false;
  }

  if (args.size() < passwd_prefix.length() + passwd_len_base32)
    goto burn;

  const uint8_t* passwd_base32 = reinterpret_cast<const uint8_t*>(
      args.data() + passwd_prefix.length());
  size_t len = crypto::Base32::decode(passwd_base32, passwd_len_base32,
                                      shared_secret_);
  if (len != kSharedSecretLength)
    goto burn;

  return true;
}

void Client::on_outgoing_connected() {
  // UniformDH handshake
  uniformdh_handshake_ = ::std::unique_ptr<UniformDHHandshake>(
      new UniformDHHandshake(shared_secret_));
  SL_ASSERT(uniformdh_handshake_ != nullptr);
  if (!uniformdh_handshake_->send_handshake_msg(outgoing_))
    send_socks5_response(Reply::kGENERAL_FAILURE);
}

void Client::on_incoming_data() {
  if (state_ != State::kESTABLISHED)
    return;

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  size_t len = ::evbuffer_get_length(buf);
  while (len > 0) {
    // Chop up len into MSS sized ScrambleSuit frames
    size_t frame_payload_len = ::std::min(len, kMaxPayloadLength);
    uint8_t* p = ::evbuffer_pullup(buf, frame_payload_len);
    if (p == nullptr) {
out_error:
      delete this;
      return;
    }

    // Create a header
    ::std::array<uint8_t, kHeaderLength> hdr = { 0 };
    hdr.at(16) = (frame_payload_len & 0xffff) >> 8;
    hdr.at(17) = (frame_payload_len & 0xff);
    hdr.at(18) = (frame_payload_len & 0xffff) >> 8;
    hdr.at(19) = (frame_payload_len & 0xff);
    hdr.at(20) = PacketFlags::kPAYLOAD;

    // Encrypt the header and payload
    if (!initiator_aes_.process(hdr.data() + kDigestLength,
                                kHeaderLength - kDigestLength,
                                hdr.data() + kDigestLength))
      goto out_error;
    if (!initiator_aes_.process(p, frame_payload_len, p))
      goto out_error;

    // MAC the frame
    if (!initiator_hmac_.init())
      goto out_error;
    if (!initiator_hmac_.update(hdr.data() + kDigestLength, 
                                kHeaderLength - kDigestLength))
      goto out_error;
    if (!initiator_hmac_.update(p, frame_payload_len))
      goto out_error;
    if (!initiator_hmac_.final(hdr.data(), kDigestLength))
      goto out_error;

    // Send the frame
    if (0 != ::bufferevent_write(outgoing_, hdr.data(), hdr.size()))
      goto out_error;
    if (0 != ::bufferevent_write(outgoing_, p, frame_payload_len))
      goto out_error;

    // Remove the processed payload from the rx queue
    ::evbuffer_drain(buf, frame_payload_len);

    len -= frame_payload_len;
  }
}

void Client::on_outgoing_data_connecting() {
  SL_ASSERT(state_ == State::kCONNECTING);

  // UniformDH handshake
  SL_ASSERT(uniformdh_handshake_ != nullptr);
  bool done = false;
  if (!uniformdh_handshake_->recv_handshake_msg(outgoing_, done))
    send_socks5_response(Reply::kGENERAL_FAILURE);
  else if (done) {
    // Ok, we have a shared secret now, derive the session keys
    if (kdf_scramblesuit(uniformdh_handshake_->shared_secret()))
      send_socks5_response(Reply::kSUCCEDED);
    else
      send_socks5_response(Reply::kGENERAL_FAILURE);
  }
}

void Client::on_outgoing_data() {
  if (state_ != State::kESTABLISHED)
    return;

  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
  size_t len = ::evbuffer_get_length(buf);
  while (len > 0) {
    // If we are waiting on reading a header:
    if (decode_state_ == FrameDecodeState::kREAD_HEADER) {
      // Attempt to read said header
      SL_ASSERT(decode_buf_len_ == 0);
      if (len < kHeaderLength)
        return;

      // Copy the header into the decode buffer
      if (kHeaderLength != ::evbuffer_remove(buf, decode_buf_.data(),
                                             kHeaderLength)) {
out_error:
        delete this;
        return;
      }
      decode_buf_len_ += kHeaderLength;
      len -= kHeaderLength;

      // MAC the header
      if (!responder_hmac_.init())
        goto out_error;
      if (!responder_hmac_.update(decode_buf_.data() + kDigestLength,
                                  kHeaderLength - kDigestLength))
        goto out_error;

      // Decrypt the header
      if (!responder_aes_.process(decode_buf_.data() + kDigestLength,
                                  kHeaderLength - kDigestLength,
                                  decode_buf_.data() + kDigestLength))
        goto out_error;

      // Validate that the lengths are sane
      decode_total_len_ = (decode_buf_.at(16) << 8) | decode_buf_.at(17);
      decode_payload_len_ = (decode_buf_.at(18) << 8) | decode_buf_.at(19);
      if (decode_total_len_ > kMaxPayloadLength)
        goto out_error;
      if (decode_payload_len_ > kMaxPayloadLength)
        goto out_error;
      if (decode_total_len_ < decode_payload_len_)
        goto out_error;

      decode_state_ = FrameDecodeState::kREAD_PAYLOAD;
    }

    // This can be reached after processing a header, ensure that data exists
    if (len == 0)
      return;

    SL_ASSERT(decode_state_ == FrameDecodeState::kREAD_PAYLOAD);
    int to_process = ::std::min(decode_total_len_ - (decode_buf_len_ - 
                                                    kHeaderLength),
                                len);
    SL_ASSERT(to_process + decode_buf_len_ <= decode_buf_.size());

    // Copy the data into the decode buffer
    if (to_process != ::evbuffer_remove(buf, decode_buf_.data() +
                                        decode_buf_len_, to_process))
      goto out_error;

    // MAC the encrypted payload
    if (!responder_hmac_.update(decode_buf_.data() + decode_buf_len_,
                                to_process))
      goto out_error;
    decode_buf_len_ += to_process;
    len -= to_process;

    if (decode_buf_len_ == kHeaderLength + decode_total_len_) {
      // Validate the MAC
      ::std::array<uint8_t, kDigestLength> digest;
      if (!responder_hmac_.final(digest.data(), digest.size()))
        goto out_error;
      if (!crypto::memequals(decode_buf_.data(), digest.data(), digest.size()))
        goto out_error;

      // Decrypt
      if (!responder_aes_.process(decode_buf_.data() + kHeaderLength,
                                  decode_buf_len_ - kHeaderLength,
                                  decode_buf_.data() + kHeaderLength))
        goto out_error;

      if (decode_payload_len_ > 0) {
        // If the frame is payload, relay the payload
        switch (decode_buf_.at(20)) {
        case PacketFlags::kPAYLOAD:
          if (0 != ::bufferevent_write(incoming_, decode_buf_.data() +
                                       kHeaderLength, decode_payload_len_))
            goto out_error;
          break;
        case PacketFlags::kNEW_TICKET: // FALLSTHROUGH
        case PacketFlags::kPRNG_SEED: // FALLSTHROUGH
        default:
          // Just ignore unknown/unsupported frame types
          break;
        }
      }

      decode_state_ = FrameDecodeState::kREAD_HEADER;
      decode_buf_len_ = 0;
    } else
      SL_ASSERT(decode_buf_len_ < kHeaderLength + kMaxPayloadLength);
  }
}

void Client::on_outgoing_drained() {
  /* When Protocol Polymorphism is supported, do something here */
}

bool Client::kdf_scramblesuit(const crypto::SecureBuffer& k_t) {
  /*
   * HKDF-SHA256-Expand(shared_secret, "", 144)
   *
   * Bytes 000:031 - 256-bit AES-CTR session key to send data.
   * Bytes 032:039 - 64-bit AES-CTR IV to send data.
   * Bytes 040:071 - 256-bit AES-CTR session key to receive data.
   * Bytes 072:079 - 64-bit AES-CTR IV to receive data.
   * Bytes 080:111 - 256-bit HMAC-SHA256-128 key to send data.
   * Bytes 112:143 - 256-bit HMAC-SHA256-128 key to receive data.
   *
   * The actual counter component is initialized to 1.
   */

  static const ::std::array<uint8_t, 8> initial_ctr = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  };

  if (k_t.size() != 32)
    return false;

  const auto prk = crypto::HkdfSha256::expand(k_t, nullptr, 0, 144);
  SL_ASSERT(prk.size() == 144);

  if (!initiator_aes_.set_state(prk.substr(0, 32),
                                prk.data() + 32, 8,
                                initial_ctr.data(),
                                initial_ctr.size()))
    return false;
  if (!responder_aes_.set_state(prk.substr(40, 32),
                                prk.data() + 72 , 8,
                                initial_ctr.data(),
                                initial_ctr.size()))
    return false;
  if (!initiator_hmac_.set_key(prk.substr(80, 32)))
    return false;
  if (!responder_hmac_.set_key(prk.substr(112, 32)))
    return false;

  return true;
}

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied
