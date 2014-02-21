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
#include <sys/time.h>

#include <event2/buffer.h>

#include "schwanenlied/crypto/base32.h"
#include "schwanenlied/crypto/hkdf_sha256.h"
#include "schwanenlied/pt/scramblesuit/client.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

constexpr char Client::kLogger[];
constexpr size_t Client::kPrngSeedLength;
constexpr size_t Client::kMaxFrameLength;
constexpr size_t Client::kMaxPayloadLength;
constexpr uint32_t Client::kMaxPacketDelay;

bool Client::on_client_authenticate(const uint8_t* uname,
                                    const uint8_t ulen,
                                    const uint8_t* passwd,
                                    const uint8_t plen) {
  static const ::std::string passwd_prefix("password=");
  static constexpr size_t passwd_len_base32 = 32;
  if ((uint16_t)ulen + plen == 0) {
    CLOG(WARNING, kLogger) << "Expected a bridge password, got nothing "
                           << "(" << this << ")";
    return false;
  }

  ::std::string args((size_t)ulen + plen, 0);
  if (uname != nullptr)
    ::std::memcpy(&args[0], uname, ulen);
  if (passwd != nullptr)
    ::std::memcpy(&args[ulen], passwd, plen);

  // One day I will write a CSV parser
  const size_t pos = args.find(passwd_prefix);
  if (pos != 0) {
    CLOG(WARNING, kLogger) << "Bridge password prefix missing, expected 'password=' "
                           << "(" << this << ")";
burn:
    crypto::memwipe(&args[0], args.size());
    return false;
  }

  if (args.size() < passwd_prefix.length() + passwd_len_base32) {
    CLOG(WARNING, kLogger) << "Bridge password under-sized, expected 32 bytes "
                           << "(" << this << ")";
    goto burn;
  }

  const uint8_t* passwd_base32 = reinterpret_cast<const uint8_t*>(
      args.data() + passwd_prefix.length());
  const size_t len = crypto::Base32::decode(passwd_base32, passwd_len_base32,
                                            shared_secret_);
  if (len != kSharedSecretLength) {
    CLOG(WARNING, kLogger) << "Bridge password decode failure "
                           << "(" << this << ")";
    goto burn;
  }

  return true;
}

void Client::on_outgoing_connected() {
  // Dump the initial probability tables
  CLOG(DEBUG, kLogger) << "Packet length probabilities: "
                       << packet_len_rng_.to_string();

  // UniformDH handshake
  uniformdh_handshake_ = ::std::unique_ptr<UniformDHHandshake>(
      new UniformDHHandshake(shared_secret_));
  SL_ASSERT(uniformdh_handshake_ != nullptr);
  if (!uniformdh_handshake_->send_handshake_msg(outgoing_)) {
    CLOG(WARNING, kLogger) << "Initiator UniformDH handshake failed "
                           << "(" << this << ")";
    send_socks5_response(Reply::kGENERAL_FAILURE);
  }
}

void Client::on_incoming_data() {
  if (state_ != State::kESTABLISHED)
    return;

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  CLOG(DEBUG, kLogger) << "on_incoming_data(): Have " << len << " bytes";

  // Schedule the next transmit
  if (!schedule_iat_transmit()) {
    delete this;
    return;
  }
}

void Client::on_outgoing_data_connecting() {
  SL_ASSERT(state_ == State::kCONNECTING);

  // UniformDH handshake
  SL_ASSERT(uniformdh_handshake_ != nullptr);
  bool done = false;
  if (!uniformdh_handshake_->recv_handshake_msg(outgoing_, done)) {
    CLOG(WARNING, kLogger) << "UniformDH handshake failed "
                           << "(" << this << ")";
    send_socks5_response(Reply::kGENERAL_FAILURE);
  } else if (done) {
    // Ok, we have a shared secret now, derive the session keys
    if (kdf_scramblesuit(uniformdh_handshake_->shared_secret())) {
      CLOG(INFO, kLogger) << "Finished UniformDH handshake "
                          << "(" << this << ": " << client_addr_str_ << " <-> "
                                 << remote_addr_str_ << ")";
      send_socks5_response(Reply::kSUCCEDED);
    } else {
      CLOG(ERROR, kLogger) << "Failed to derive session keys "
                           << "(" << this << ")";
      send_socks5_response(Reply::kGENERAL_FAILURE);
    }
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
      if (static_cast<int>(kHeaderLength) != ::evbuffer_remove(buf,
                                                               decode_buf_.data(),
                                                               kHeaderLength)) {
        CLOG(ERROR, kLogger) << "Failed to read frame header "
                             << "(" << this << ")";
out_error:
        delete this;
        return;
      }
      decode_buf_len_ += kHeaderLength;
      len -= kHeaderLength;

      // MAC the header
      if (!responder_hmac_.init()) {
        CLOG(ERROR, kLogger) << "Failed to init RX frame MAC "
                             << "(" << this << ")";
        goto out_error;
      }
      if (!responder_hmac_.update(decode_buf_.data() + kDigestLength,
                                  kHeaderLength - kDigestLength)) {
        CLOG(ERROR, kLogger) << "Failed to MAC RX frame header "
                             << "(" << this << ")";
        goto out_error;
      }

      // Decrypt the header
      if (!responder_aes_.process(decode_buf_.data() + kDigestLength,
                                  kHeaderLength - kDigestLength,
                                  decode_buf_.data() + kDigestLength)) {
        CLOG(ERROR, kLogger) << "Failed to decrypt frame header "
                             << "(" << this << ")";
        goto out_error;
      }

      // Validate that the lengths are sane
      decode_total_len_ = (decode_buf_.at(16) << 8) | decode_buf_.at(17);
      decode_payload_len_ = (decode_buf_.at(18) << 8) | decode_buf_.at(19);
      if (decode_total_len_ > kMaxPayloadLength) {
        CLOG(WARNING, kLogger) << "Total length oversized: " << decode_total_len_ << " "
                               << "(" << this << ")";
        goto out_error;
      }
      if (decode_payload_len_ > kMaxPayloadLength) {
        CLOG(WARNING, kLogger) << "Payload length oversized: " << decode_payload_len_ << " "
                               << "(" << this << ")";
        goto out_error;
      }
      if (decode_total_len_ < decode_payload_len_) {
        CLOG(WARNING, kLogger) << "Payload longer than frame: "
                               << decode_total_len_ << " < " << decode_payload_len_ << " "
                               << "(" << this << ")";
        goto out_error;
      }

      decode_state_ = FrameDecodeState::kREAD_PAYLOAD;
    }

    // This can be reached after processing a header, ensure that data exists
    if (len == 0)
      return;

    SL_ASSERT(decode_state_ == FrameDecodeState::kREAD_PAYLOAD);
    const int to_process = ::std::min(decode_total_len_ - (decode_buf_len_ - 
                                                           kHeaderLength), len);
    SL_ASSERT(to_process + decode_buf_len_ <= decode_buf_.size());

    // Copy the data into the decode buffer
    if (to_process != ::evbuffer_remove(buf, decode_buf_.data() +
                                        decode_buf_len_, to_process)) {
      CLOG(ERROR, kLogger) << "Failed to read frame payload "
                           << "(" << this << ")";
      goto out_error;
    }

    // MAC the encrypted payload
    if (!responder_hmac_.update(decode_buf_.data() + decode_buf_len_,
                                to_process)) {
      CLOG(ERROR, kLogger) << "Failed to MAC RX frame payload "
                           << "(" << this << ")";
      goto out_error;
    }
    decode_buf_len_ += to_process;
    len -= to_process;

    if (decode_buf_len_ == kHeaderLength + decode_total_len_) {
      // Validate the MAC
      ::std::array<uint8_t, kDigestLength> digest;
      if (!responder_hmac_.final(digest.data(), digest.size())) {
        CLOG(ERROR, kLogger) << "Failed to finalize RX frame MAC "
                             << "(" << this << ")";
        goto out_error;
      }
      if (!crypto::memequals(decode_buf_.data(), digest.data(), digest.size())) {
        CLOG(ERROR, kLogger) << "RX frame MAC mismatch "
                             << "(" << this << ")";
        goto out_error;
      }

      // Decrypt
      if (!responder_aes_.process(decode_buf_.data() + kHeaderLength,
                                  decode_buf_len_ - kHeaderLength,
                                  decode_buf_.data() + kHeaderLength)) {
        CLOG(ERROR, kLogger) << "Failed to decrypt frame payload "
                             << "(" << this << ")";
        goto out_error;
      }

      CLOG(DEBUG, kLogger) << "Received " << kHeaderLength << " + "
                                          << decode_payload_len_ << " + "
                                          << (decode_total_len_ - decode_payload_len_)
                                          << " bytes from peer "
                           << "(" << this << ")";

      if (decode_payload_len_ > 0) {
        // If the frame is payload, relay the payload
        switch (decode_buf_.at(20)) {
        case PacketFlags::kPAYLOAD:
          if (0 != ::bufferevent_write(incoming_, decode_buf_.data() +
                                       kHeaderLength, decode_payload_len_)) {
            CLOG(ERROR, kLogger) << "Failed to send remote payload "
                                 << "(" << this << ")";
            goto out_error;
          }
          break;
        case PacketFlags::kPRNG_SEED:
          if (decode_payload_len_ != kPrngSeedLength) {
            CLOG(WARNING, kLogger) << "Received invalid PRNG seed, ignoring";
            break;
          }
          CLOG(INFO, kLogger) << "Received new PRNG seed, morphing";
          packet_len_rng_.reset(decode_buf_.data() + kHeaderLength,
                                decode_payload_len_, kHeaderLength,
                                kMaxFrameLength);
          packet_int_rng_.reset(decode_buf_.data() + kHeaderLength,
                                decode_payload_len_, 0,
                                kMaxPacketDelay);
          CLOG(DEBUG, kLogger) << "Packet length probabilities: "
                               << packet_len_rng_.to_string();
          CLOG(DEBUG, kLogger) << "Packet interval probabilities (x100 usec): "
                               << packet_int_rng_.to_string();
          break;
        case PacketFlags::kNEW_TICKET: // FALLSTHROUGH
        default:
          // Just ignore unknown/unsupported frame types
          CLOG(WARNING, kLogger) << "Received unsupported frame type: "
                                 << static_cast<int>(decode_buf_.at(20)) << " "
                                 << "(" << this << ")";
          break;
        }
      }

      decode_state_ = FrameDecodeState::kREAD_HEADER;
      decode_buf_len_ = 0;
    } else
      SL_ASSERT(decode_buf_len_ < kHeaderLength + kMaxPayloadLength);
  }
}

bool Client::on_outgoing_flush() {
  /*
   * This is called when incoming_ is closed, and the base instance wants to
   * know if it is safe to discard the session.  The first call is from the
   * incoming_ event callback, all other subsequent calls will be made when
   * outgoing_'s write buffer is drained (which is defered).
   *
   * If the timer is pending, then there is data queued for transmission.  If
   * incoming_'s read buffer is drained, the timer won't be pending, so it's
   * safe to flush things.
   */
  return !evtimer_pending(iat_timer_ev_, NULL);
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

  static constexpr ::std::array<uint8_t, 8> initial_ctr = { {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  } };

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

bool Client::schedule_iat_transmit() {
  // Lazy timer initialization
  if (iat_timer_ev_ == nullptr) {
    event_callback_fn cb = [](evutil_socket_t sock,
                              short witch,
                              void* arg) {
      reinterpret_cast<Client*>(arg)->on_iat_transmit();
    };
    iat_timer_ev_ = evtimer_new(base_, cb, this);
    if (iat_timer_ev_ == nullptr) {
      CLOG(ERROR, kLogger) << "Failed to initialize IAT timer";
      return false;
    }
  }

  // If the IAT timer is pending, then return (Should never happen)
  if (evtimer_pending(iat_timer_ev_, NULL)) {
    CLOG(DEBUG, kLogger) << "schedule_iat_transmit() called when pending?";
    return true;
  }

  // Schedule the next transmit based off the RNG
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = packet_int_rng_() * 100;
  evtimer_add(iat_timer_ev_, &tv);

  CLOG(DEBUG, kLogger) << "Next IAT TX in: " << tv.tv_usec << " usec";

  return true;
}

void Client::on_iat_transmit() {
  if (state_ != State::kESTABLISHED && state_ != State::kFLUSHING_OUTGOING)
    return;

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  const size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return;

  CLOG(DEBUG, kLogger) << "on_iat_transmit(): Have " << len << " bytes";

  const size_t frame_payload_len = ::std::min(len, kMaxPayloadLength);
  uint8_t* p = ::evbuffer_pullup(buf, frame_payload_len);
  if (p == nullptr) {
    CLOG(ERROR, kLogger) << "Failed to pullup buffer "
                         << "(" << this << ")";
out_error:
    delete this;
    return;
  }

  size_t pad_len = 0;
  if (frame_payload_len < kMaxPayloadLength || len == kMaxPayloadLength) {
    /*
     * Only append padding if the transmitted frame is not full sized, unless
     * sending a full sized frame will completely drain the IAT buffer.
     *
     * I don't *think* that sending full frames without padding in the case of
     * sustained data transfer is something that's fingerprintable and it would
     * look more suspicious if "sustained" bursts had random padding.
     */
    const size_t burst_tail_len = frame_payload_len % kMaxFrameLength;
    const uint32_t sample_len = packet_len_rng_();
    if (sample_len >= burst_tail_len)
      pad_len = sample_len - burst_tail_len;
    else
      pad_len = (kMaxFrameLength - burst_tail_len) + sample_len;
  }

  if (pad_len >= kHeaderLength && pad_len + frame_payload_len <= kMaxPayloadLength) {
    // XXX: In theory, it's possible to incrementally send padding as well?
    if (!send_outgoing_frame(p, frame_payload_len, pad_len - kHeaderLength))
      goto out_error;
    pad_len = 0;
  } else if (!send_outgoing_frame(p, frame_payload_len, 0))
    goto out_error;

  // Remove the processed payload from the rx queue
  ::evbuffer_drain(buf, frame_payload_len);

  // Send remaining padding if any exists
  if (pad_len > kHeaderLength) {
    if (!send_outgoing_frame(nullptr, 0, pad_len - kHeaderLength))
      goto out_error;
  } else if (pad_len > 0) {
    if (!send_outgoing_frame(nullptr, 0, kMaxPayloadLength - kHeaderLength))
      goto out_error;
    if (!send_outgoing_frame(nullptr, 0, pad_len))
      goto out_error;
  }

  if (::evbuffer_get_length(buf) > 0) {
    if (!schedule_iat_transmit())
      goto out_error;
  } else
    CLOG(DEBUG, kLogger) << "IAT TX buffer drained";
}

bool Client::send_outgoing_frame(const uint8_t* buf,
                                 const size_t len,
                                 const size_t pad_len) {
  if (len == 0 && buf != nullptr)
    return false;
  if (buf == nullptr && len != 0)
    return false;
  if (len + pad_len + kHeaderLength > kMaxFrameLength)
    return false;
  if (len > kMaxPayloadLength)
    return false;
  if (pad_len > kMaxPayloadLength)
    return false;

  // Create a header
  const size_t frame_payload_len = len + pad_len;
  ::std::array<uint8_t, kHeaderLength> hdr = {};
  hdr.at(16) = (frame_payload_len & 0xffff) >> 8;
  hdr.at(17) = (frame_payload_len & 0xff);
  hdr.at(18) = (len & 0xffff) >> 8;
  hdr.at(19) = (len & 0xff);
  hdr.at(20) = PacketFlags::kPAYLOAD;

  // Encrypt the header
  if (!initiator_aes_.process(hdr.data() + kDigestLength,
                              kHeaderLength - kDigestLength,
                              hdr.data() + kDigestLength)) {
    CLOG(ERROR, kLogger) << "Failed to encrypt frame header "
                         << "(" << this << ")";
    return false;
  }

  // Generate the payload/padding
  ::std::array<uint8_t, kMaxPayloadLength> payload = {};
  SL_ASSERT(payload.size() >= frame_payload_len);
  if (len > 0) {
    if (!initiator_aes_.process(buf, len, payload.data())) {
      CLOG(ERROR, kLogger) << "Failed to encrypt frame payload "
                           << "(" << this << ")";
      return false;
    }
  }
  if (pad_len > 0) {
    if (!initiator_aes_.process(payload.data() + len, pad_len, payload.data() +
                                len)) {
      CLOG(ERROR, kLogger) << "Failed to encrypt frame padding "
                           << "(" << this << ")";
      return false;
    }
  }

  // MAC the frame
  if (!initiator_hmac_.init()) {
    CLOG(ERROR, kLogger) << "Failed to init TX frame MAC "
                         << "(" << this << ")";
    return false;
  }
  if (!initiator_hmac_.update(hdr.data() + kDigestLength,
                              kHeaderLength - kDigestLength)) {
    CLOG(ERROR, kLogger) << "Failed to MAC TX frame header "
                         << "(" << this << ")";
    return false;
  }
  if (!initiator_hmac_.update(payload.data(), frame_payload_len)) {
    CLOG(ERROR, kLogger) << "Failed to MAC TX frame payload "
                         << "(" << this << ")";
    return false;
  }
  if (!initiator_hmac_.final(hdr.data(), kDigestLength)) {
    CLOG(ERROR, kLogger) << "Failed to finalize TX frame MAC "
                         << "(" << this << ")";
    return false;
  }

  // Send the frame
  if (0 != ::bufferevent_write(outgoing_, hdr.data(), hdr.size())) {
    CLOG(ERROR, kLogger) << "Failed to send frame header "
                         << "(" << this << ")";
    return false;
  }
  if (0 != ::bufferevent_write(outgoing_, payload.data(), frame_payload_len)) {
    CLOG(ERROR, kLogger) << "Failed to send frame payload "
                         << "(" << this << ")";
    return false;
  }

  CLOG(DEBUG, kLogger) << "Sent " << hdr.size() << " + " << len << " + "
                       << pad_len << " bytes to peer "
                       << "(" << this << ")";

  return true;
}

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied
