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

#define SCRAMBLESUIT_CLIENT_IMPL

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

constexpr size_t Client::kPrngSeedLength;
constexpr size_t Client::kMaxFrameLength;
constexpr size_t Client::kMaxPayloadLength;
#ifdef ENABLE_SCRAMBLESUIT_IAT
constexpr uint32_t Client::kMaxPacketDelay;
#endif

bool Client::on_client_authenticate(const uint8_t* uname,
                                    const uint8_t ulen,
                                    const uint8_t* passwd,
                                    const uint8_t plen) {
  static const ::std::string passwd_prefix("password=");
  static constexpr size_t passwd_len_base32 = 32;

  /* Yes, 2, because ulen/plen are >= 1 per the socks spec */
  if (static_cast<uint16_t>(ulen) + plen <= 2) {
    LOG(WARNING) << this << ": Expected a bridge password, got nothing";
    return false;
  }

  /*
   * Jam the uname/passwd fields together.  Since the basic username/password
   * auth algorithm has mandetory field sizes of 1, also trim off any trailing
   * NUL characters.
   */
  ::std::string args(static_cast<size_t>(ulen) + plen, 0);
  if (uname != nullptr)
    ::std::memcpy(&args[0], uname, ulen);
  if (passwd != nullptr)
    ::std::memcpy(&args[ulen], passwd, plen);
  const auto tail = args.find_last_not_of('\0');
  if (tail != ::std::string::npos)
    args.erase(tail + 1);

  // One day I will write a CSV parser
  const size_t pos = args.find(passwd_prefix);
  if (pos != 0) {
    LOG(WARNING) << this << ": Bridge password prefix missing, expected 'password=' ";
burn:
    crypto::memwipe(&args[0], args.size());
    return false;
  }

  if (args.size() != passwd_prefix.size() + passwd_len_base32) {
    LOG(WARNING) << this << ": Bridge password length invalid, expected 32 bytes";
    goto burn;
  }

  const uint8_t* passwd_base32 = reinterpret_cast<const uint8_t*>(
      args.data() + passwd_prefix.size());
  const size_t len = crypto::Base32::decode(passwd_base32, passwd_len_base32,
                                            shared_secret_);
  if (len != kSharedSecretLength) {
    LOG(WARNING) << this << ": Bridge password decode failure";
    goto burn;
  }

  return true;
}

bool Client::on_outgoing_connected() {
  // Dump the initial probability tables
  LOG(DEBUG) << this << ": Packet length probabilities: "
             << packet_len_rng_.to_string();

  // Session Ticket Handshake
  session_ticket_handshake_ = ::std::unique_ptr<SessionTicketHandshake>(
      new SessionTicketHandshake(*this,
                                 server_.state_dir(),
                                 reinterpret_cast<struct sockaddr*>(&remote_addr_),
                                 remote_addr_len_));
  bool done = false;
  if (session_ticket_handshake_ == nullptr) {
    LOG(ERROR) << this << ": Failed to allocate Session Ticket Handshake";
    return send_socks5_response(Reply::kGENERAL_FAILURE);
  } else if (!session_ticket_handshake_->send_handshake_msg(done)) {
    // Something went horribly wrong and we couldn't send a ticket
    LOG(WARNING) << this << ": Initiator Session Ticket handshake failed";
    return send_socks5_response(Reply::kGENERAL_FAILURE);
  } else if (done) {
    /*
     * The Session Ticket Handshake 'succeeds' immediately after sending a
     * ticket, and if it actually fails due to an invalid ticket, the peer
     * will drop the connection.
     *
     * We will defer sending the SOCKS5 response till the peer actually sends
     * data because obfsproxy doesn't have a timeout on incoming connections.
     */
    LOG(INFO) << this << ": Session Ticket handshake sent";
    handshake_ = HandshakeMethod::kSESSION_TICKET;
    return true;
  } else {
    // UniformDH handshake
    handshake_ = HandshakeMethod::kUNIFORM_DH;
    uniformdh_handshake_ = ::std::unique_ptr<UniformDHHandshake>(
        new UniformDHHandshake(*this, shared_secret_));
    if (uniformdh_handshake_ == nullptr) {
      LOG(ERROR) << this << ": Failed to allocate UniformDH Handshake";
      return send_socks5_response(Reply::kGENERAL_FAILURE);
    } else if (!uniformdh_handshake_->send_handshake_msg()) {
      LOG(WARNING) << this << ": Initiator UniformDH handshake failed";
      return send_socks5_response(Reply::kGENERAL_FAILURE);
    }
    return true;
  }
}

bool Client::on_incoming_data() {
  SL_ASSERT(state_ == State::kESTABLISHED);

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return true;

  LOG(DEBUG) << this << ": on_incoming_data(): Have " << len << " bytes";

#ifdef ENABLE_SCRAMBLESUIT_IAT
  // Schedule the next transmit
  if (!schedule_iat_transmit()) {
    server_.close_session(this);
    return false;
  }

  return true;
#else
  // Transmit the entire buffer
  return on_iat_transmit(true);
#endif
}

bool Client::on_outgoing_data_connecting() {
  SL_ASSERT(state_ == State::kCONNECTING);

  if (handshake_ == HandshakeMethod::kSESSION_TICKET) {
    // Session Ticket handshake
    SL_ASSERT(session_ticket_handshake_ != nullptr);
    SL_ASSERT(uniformdh_handshake_ == nullptr);

    LOG(INFO) << this << ": Finished SessionTicket handshake";

    /*
     * Ok, the peer sent what I imagine to be a frame, the session is probably
     * established.  If send_socks5_response fails, it will clean up the
     * session.
     */
    if (send_socks5_response(Reply::kSUCCEDED)) {
      /*
       * Manually invoke the callback that caused this one to get triggered in
       * the first place.
       */
      return on_outgoing_data();
    }

    return true;
  } else if (handshake_ == HandshakeMethod::kUNIFORM_DH) {
    // UniformDH handshake
    SL_ASSERT(uniformdh_handshake_ != nullptr);
    bool done = false;
    if (!uniformdh_handshake_->recv_handshake_msg(done)) {
      LOG(WARNING) << this << ": UniformDH handshake failed";
      return send_socks5_response(Reply::kGENERAL_FAILURE);
    } else if (done) {
      // Free up the UniformDH keypair (dtor won't be called for a while)
      uniformdh_handshake_.reset(nullptr);

      LOG(INFO) << this << ": Finished UniformDH handshake";
      return send_socks5_response(Reply::kSUCCEDED);
    }

    return true;
  } else
    SL_ABORT("Unknown handshake type");
}

bool Client::on_outgoing_data() {
  SL_ASSERT(state_ == State::kESTABLISHED);

  struct evbuffer* buf = ::bufferevent_get_input(outgoing_);
  size_t len = ::evbuffer_get_length(buf);
  while (len > 0) {
    // If we are waiting on reading a header:
    if (decode_state_ == FrameDecodeState::kREAD_HEADER) {
      // Attempt to read said header
      SL_ASSERT(decode_buf_len_ == 0);
      if (len < kHeaderLength)
        return true;

      // Copy the header into the decode buffer
      if (static_cast<int>(kHeaderLength) != ::evbuffer_remove(buf,
                                                               decode_buf_.data(),
                                                               kHeaderLength)) {
        LOG(ERROR) << this << ": Failed to read frame header";
        server_.close_session(this);
        return false;
      }
      decode_buf_len_ += kHeaderLength;
      len -= kHeaderLength;

      // MAC the header
      if (!responder_hmac_.init()) {
        LOG(ERROR) << this << ": Failed to init RX frame MAC";
        server_.close_session(this);
        return false;
      }
      if (!responder_hmac_.update(decode_buf_.data() + kDigestLength,
                                  kHeaderLength - kDigestLength)) {
        LOG(ERROR) << this << ": Failed to MAC RX frame header";
        server_.close_session(this);
        return false;
      }

      // Decrypt the header
      if (!responder_aes_.process(decode_buf_.data() + kDigestLength,
                                  kHeaderLength - kDigestLength,
                                  decode_buf_.data() + kDigestLength)) {
        LOG(ERROR) << this << ": Failed to decrypt frame header";
        server_.close_session(this);
        return false;
      }

      // Validate that the lengths are sane
      decode_total_len_ = (decode_buf_.at(16) << 8) | decode_buf_.at(17);
      decode_payload_len_ = (decode_buf_.at(18) << 8) | decode_buf_.at(19);
      if (decode_total_len_ > kMaxPayloadLength) {
        LOG(WARNING) << this << ": Total length oversized: " << decode_total_len_;
        server_.close_session(this);
        return false;
      }
      if (decode_payload_len_ > kMaxPayloadLength) {
        LOG(WARNING) << this << ": Payload length oversized: " << decode_payload_len_;
        server_.close_session(this);
        return false;
      }
      if (decode_total_len_ < decode_payload_len_) {
        LOG(WARNING) << this << ": Payload longer than frame: "
                     << decode_total_len_ << " < " << decode_payload_len_;
        server_.close_session(this);
        return false;
      }

      decode_state_ = FrameDecodeState::kREAD_PAYLOAD;
    }

    // This can be reached after processing a header, ensure that data exists
    if (len == 0)
      return true;

    SL_ASSERT(decode_state_ == FrameDecodeState::kREAD_PAYLOAD);
    const int to_process = ::std::min(decode_total_len_ - (decode_buf_len_ - 
                                                           kHeaderLength), len);
    SL_ASSERT(to_process + decode_buf_len_ <= decode_buf_.size());

    // Copy the data into the decode buffer
    if (to_process != ::evbuffer_remove(buf, decode_buf_.data() +
                                        decode_buf_len_, to_process)) {
      LOG(ERROR) << this << ": Failed to read frame payload";
      server_.close_session(this);
      return false;
    }

    // MAC the encrypted payload
    if (!responder_hmac_.update(decode_buf_.data() + decode_buf_len_,
                                to_process)) {
      LOG(ERROR) << this << ": Failed to MAC RX frame payload";
      server_.close_session(this);
      return false;
    }
    decode_buf_len_ += to_process;
    len -= to_process;

    if (decode_buf_len_ == kHeaderLength + decode_total_len_) {
      // Validate the MAC
      ::std::array<uint8_t, kDigestLength> digest;
      if (!responder_hmac_.final(digest.data(), digest.size())) {
        LOG(ERROR) << this << ": Failed to finalize RX frame MAC";
        server_.close_session(this);
        return false;
      }
      if (!crypto::memequals(decode_buf_.data(), digest.data(), digest.size())) {
        LOG(ERROR) << this << ": RX frame MAC mismatch";
        server_.close_session(this);
        return false;
      }

      // Decrypt
      if (!responder_aes_.process(decode_buf_.data() + kHeaderLength,
                                  decode_buf_len_ - kHeaderLength,
                                  decode_buf_.data() + kHeaderLength)) {
        LOG(ERROR) << this << ": Failed to decrypt frame payload";
        server_.close_session(this);
        return false;
      }

      LOG(DEBUG) << this << ": Received " << kHeaderLength << " + "
                 << decode_payload_len_ << " + "
                 << (decode_total_len_ - decode_payload_len_)
                 << " bytes from peer";

      if (decode_payload_len_ > 0) {
        // If the frame is payload, relay the payload
        switch (decode_buf_.at(20)) {
        case PacketFlags::kPAYLOAD:
          if (0 != ::bufferevent_write(incoming_, decode_buf_.data() +
                                       kHeaderLength, decode_payload_len_)) {
            LOG(ERROR) << this << ": Failed to send remote payload";
            server_.close_session(this);
            return false;
          }
          break;
        case PacketFlags::kPRNG_SEED:
          if (decode_payload_len_ != kPrngSeedLength) {
            LOG(WARNING) << this << ": Received invalid PRNG seed, ignoring";
            break;
          }
          LOG(INFO) << this << ": Received new PRNG seed, morphing";
          packet_len_rng_.reset(decode_buf_.data() + kHeaderLength,
                                decode_payload_len_, kHeaderLength,
                                kMaxFrameLength);
          LOG(DEBUG) << this << ": Packet length probabilities: "
                     << packet_len_rng_.to_string();
#ifdef ENABLE_SCRAMBLESUIT_IAT
          packet_int_rng_.reset(decode_buf_.data() + kHeaderLength,
                                decode_payload_len_, 0,
                                kMaxPacketDelay);
          LOG(DEBUG) << this << ": Packet interval probabilities (x100 usec): "
                     << packet_int_rng_.to_string();
#endif
          break;
        case PacketFlags::kNEW_TICKET:
          LOG(INFO) << this << ": Received new Session Ticket, persisting";
          SL_ASSERT(session_ticket_handshake_ != nullptr);
          session_ticket_handshake_->on_new_ticket(decode_buf_.data() + kHeaderLength,
                                                   decode_payload_len_);
          break;
        default:
          // Just ignore unknown/unsupported frame types
          LOG(WARNING) << this << ": Received unsupported frame type: "
                       << static_cast<int>(decode_buf_.at(20));
          break;
        }
      }

      decode_state_ = FrameDecodeState::kREAD_HEADER;
      decode_buf_len_ = 0;
    } else
      SL_ASSERT(decode_buf_len_ < kHeaderLength + kMaxPayloadLength);
  }

  return true;
}

#ifdef ENABLE_SCRAMBLESUIT_IAT
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

  if (iat_timer_ev_ == nullptr)
    return true;

  return !evtimer_pending(iat_timer_ev_, nullptr);
}
#endif

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

#ifdef ENABLE_SCRAMBLESUIT_IAT
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
      LOG(ERROR) << this << ": Failed to initialize IAT timer";
      return false;
    }
  }

  // If the IAT timer is pending, then return
  if (evtimer_pending(iat_timer_ev_, NULL))
    return true;

  // Schedule the next transmit based off the RNG
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = packet_int_rng_() * 100;
  evtimer_add(iat_timer_ev_, &tv);

  LOG(DEBUG) << this << ": Next IAT TX in: " << tv.tv_usec << " usec";

  return true;
}
#endif

bool Client::on_iat_transmit(const bool send_all) {
  if (state_ != State::kESTABLISHED && state_ != State::kFLUSHING_OUTGOING)
    return false;

  struct evbuffer* buf = ::bufferevent_get_input(incoming_);
  size_t len = ::evbuffer_get_length(buf);
  if (len == 0)
    return true;

  LOG(DEBUG) << this << ": on_iat_transmit(): Have " << len << " bytes";

  do {
    const size_t frame_payload_len = ::std::min(len, kMaxPayloadLength);
    uint8_t* p = ::evbuffer_pullup(buf, frame_payload_len);
    if (p == nullptr) {
      LOG(ERROR) << this << ": Failed to pullup buffer";
      server_.close_session(this);
      return false;
    }

    size_t pad_len = 0;
    if (frame_payload_len < kMaxPayloadLength || len == kMaxPayloadLength) {
      /*
       * Only append padding if the transmitted frame is not full sized, unless
       * sending a full sized frame will completely drain the IAT buffer.
       *
       * I don't *think* that sending full frames without padding in the case of
       * sustained data transfer is something that's fingerprintable and it
       * would look more suspicious if "sustained" bursts had random padding.
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
      if (!send_outgoing_frame(p, frame_payload_len, pad_len - kHeaderLength)) {
        server_.close_session(this);
        return false;
      }
      pad_len = 0;
    } else if (!send_outgoing_frame(p, frame_payload_len, 0)) {
      server_.close_session(this);
      return false;
    }

    // Remove the processed payload from the rx queue
    ::evbuffer_drain(buf, frame_payload_len);
    len = ::evbuffer_get_length(buf);

    // Send remaining padding if any exists
    if (pad_len > kHeaderLength) {
      if (!send_outgoing_frame(nullptr, 0, pad_len - kHeaderLength)) {
        server_.close_session(this);
        return false;
      }
    } else if (pad_len > 0) {
      if (!send_outgoing_frame(nullptr, 0, kMaxPayloadLength - kHeaderLength)) {
        server_.close_session(this);
        return false;
      }
      if (!send_outgoing_frame(nullptr, 0, pad_len)) {
        server_.close_session(this);
        return false;
      }
    }
  } while (send_all && len > 0);

#ifdef ENABLE_SCRAMBLESUIT_IAT
  if (len > 0) {
    if (!schedule_iat_transmit()) {
      server_.close_session(this);
      return false;
    }
  } else
    LOG(DEBUG) << this << ": IAT TX buffer drained";
#endif

  return true;
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
    LOG(ERROR) << this << ": Failed to encrypt frame header";
    return false;
  }

  // Generate the payload/padding
  ::std::array<uint8_t, kMaxPayloadLength> payload = {};
  SL_ASSERT(payload.size() >= frame_payload_len);
  if (len > 0) {
    if (!initiator_aes_.process(buf, len, payload.data())) {
      LOG(ERROR) << this << ": Failed to encrypt frame payload";
      return false;
    }
  }
  if (pad_len > 0) {
    if (!initiator_aes_.process(payload.data() + len, pad_len, payload.data() +
                                len)) {
      LOG(ERROR) << this << ": Failed to encrypt frame padding";
      return false;
    }
  }

  // MAC the frame
  if (!initiator_hmac_.init()) {
    LOG(ERROR) << this << ": Failed to init TX frame MAC";
    return false;
  }
  if (!initiator_hmac_.update(hdr.data() + kDigestLength,
                              kHeaderLength - kDigestLength)) {
    LOG(ERROR) << this << ": Failed to MAC TX frame header";
    return false;
  }
  if (!initiator_hmac_.update(payload.data(), frame_payload_len)) {
    LOG(ERROR) << this << ": Failed to MAC TX frame payload";
    return false;
  }
  if (!initiator_hmac_.final(hdr.data(), kDigestLength)) {
    LOG(ERROR) << this << ": Failed to finalize TX frame MAC";
    return false;
  }

  // Send the frame
  if (0 != ::bufferevent_write(outgoing_, hdr.data(), hdr.size())) {
    LOG(ERROR) << this << ": Failed to send frame header";
    return false;
  }
  if (0 != ::bufferevent_write(outgoing_, payload.data(), frame_payload_len)) {
    LOG(ERROR) << this << ": Failed to send frame payload";
    return false;
  }

  LOG(DEBUG) << this << ": Sent " << hdr.size() << " + " << len << " + "
             << pad_len << " bytes to peer";

  return true;
}

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied
