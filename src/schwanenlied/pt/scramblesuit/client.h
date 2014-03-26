/**
 * @file    scramblesuit/client.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit Client
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

#ifndef SCHWANENLIED_PT_SCRAMBLESUIT_CLIENT_H__
#define SCHWANENLIED_PT_SCRAMBLESUIT_CLIENT_H__

#define SCRAMBLESUIT_LOGGER "scramblesuit"
#ifdef SCRAMBLESUIT_CLIENT_IMPL
#define _LOGGER SCRAMBLESUIT_LOGGER
#endif

#include <array>

#include <event2/event.h>

#include "schwanenlied/common.h"
#include "schwanenlied/socks5_server.h"
#include "schwanenlied/crypto/aes.h"
#include "schwanenlied/crypto/hmac_sha256.h"
#include "schwanenlied/pt/scramblesuit/prob_dist.h"
#include "schwanenlied/pt/scramblesuit/session_ticket_handshake.h"
#include "schwanenlied/pt/scramblesuit/uniform_dh_handshake.h"

namespace schwanenlied {
namespace pt {

/** ScrambleSuit */
namespace scramblesuit {

/**
 * ScrambleSuit Client
 *
 * This implements a wire compatible ScrambleSuit client using Socks5Server.
 */
class Client : public Socks5Server::Session {
 public:
  /** Client factory */
  class SessionFactory : public Socks5Server::SessionFactory {
   public:
    Socks5Server::Session* create_session(Socks5Server& server,
                                          struct event_base* base,
                                          const evutil_socket_t sock,
                                          const ::std::string& addr,
                                          const bool scrub_addrs) override {
      return static_cast<Socks5Server::Session*>(new Client(server, base, sock,
                                                            addr, scrub_addrs));
    }
  };

  Client(Socks5Server& server,
         struct event_base* base,
         const evutil_socket_t sock,
         const ::std::string& addr,
         const bool scrub_addrs) :
      Session(server, base, sock, addr, true, scrub_addrs),
      logger_(::el::Loggers::getLogger(SCRAMBLESUIT_LOGGER)),
      handshake_(HandshakeMethod::kINVALID),
      packet_len_rng_(kHeaderLength, kMaxFrameLength),
#ifdef ENABLE_SCRAMBLESUIT_IAT
      packet_int_rng_(0, kMaxPacketDelay),
      iat_timer_ev_(nullptr),
#endif
      decode_state_(FrameDecodeState::kREAD_HEADER),
      decode_buf_len_(0),
      decode_total_len_(0),
      decode_payload_len_(0) {}

  ~Client() {
#ifdef ENABLE_SCRAMBLESUIT_IAT
    if (iat_timer_ev_ != nullptr)
      ::event_free(iat_timer_ev_);
#endif
  }

 protected:
  bool on_client_authenticate(const uint8_t* uname,
                              const uint8_t ulen,
                              const uint8_t* passwd,
                              const uint8_t plen) override;

  bool on_outgoing_connected() override;

  bool on_incoming_data() override;

  bool on_outgoing_data_connecting() override;

  bool on_outgoing_data() override;

#ifdef ENABLE_SCRAMBLESUIT_IAT
  bool on_outgoing_flush() override;
#endif

 private:
  Client(const Client&) = delete;
  void operator=(const Client&) = delete;

  /** @{ */
  /** k_B length */
  static constexpr size_t kSharedSecretLength = 20;
  /** HMAC-SHA256-128 digest length */
  static constexpr size_t kDigestLength = 16;
  /** ScrambleSuit frame header length */
  static constexpr size_t kHeaderLength = 21;
  /** ScrambleSuit PRNG seed length */
  static constexpr size_t kPrngSeedLength = 32;
  /** ScrambleSuit frame max frame length */
  static constexpr size_t kMaxFrameLength = 1448;
  /** ScrambleSuit frame max payload length */
  static constexpr size_t kMaxPayloadLength = kMaxFrameLength - kHeaderLength;
#ifdef ENABLE_SCRAMBLESUIT_IAT
  /** ScrambleSuit max IAT obfsucation delay (multiples of 100 usec) */
  static constexpr uint32_t kMaxPacketDelay = 100;
#endif
  /** @} */

  /** ScrambleSuit Handshake methods */
  enum class HandshakeMethod {
    kINVALID,           /**< Unknown handshake type */
    kUNIFORM_DH,        /**< UniformDH */
    kSESSION_TICKET     /**< Session Ticket */
  };

  /** ScrambleSuit Packet Flag bitfield */
  enum PacketFlags {
    kPAYLOAD = 0x1,     /**< Payload packet */
    kNEW_TICKET = 0x2,  /**< Session ticket packet */
    kPRNG_SEED = 0x4    /**< Protocol Polymorphism PRNG seed packet */
  };

  /**
   * Given a shared secret, derive the session keys per the ScrambleSuit spec
   *
   * @param[in] k_t The shared secret to use as the key material
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool kdf_scramblesuit(const crypto::SecureBuffer& k_t);

#ifdef ENABLE_SCRAMBLESUIT_IAT
  /**
   * Schedule the Inter-Arrival Time obfuscation TX timer
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool schedule_iat_transmit();
#endif

  /**
   * Inter-Arrivial Time obfuscation TX timer callback
   *
   * @param[in] send_all  Send the entire buffer
   *
   * @returns true  - Success
   * @returns false - Failure (Object destroyed)
   */
  bool on_iat_transmit(const bool send_all=false);

  /**
   * Encode and send an outgoing ScrambleSuit frame
   *
   * @param[in] buf     The buffer to send as payload
   * @param[in] len     The length of the payload
   * @param[in] pad_len The length of the padding to append
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool send_outgoing_frame(const uint8_t* buf,
                           const size_t len,
                           const size_t pad_len);

  ::el::Logger* logger_;  /**< The scramblesuit logger */

  /** @{ */
  /** The 160 bit bridge secret (k_B) */
  crypto::SecureBuffer shared_secret_;
  /** The handshake type used */
  HandshakeMethod handshake_;
  /** The UniformDHHandshake instance */
  ::std::unique_ptr<UniformDHHandshake> uniformdh_handshake_;
  /** The SessionTicketHandshake instance */
  ::std::unique_ptr<SessionTicketHandshake> session_ticket_handshake_;
  /** @} */

  /** @{ */
  crypto::HmacSha256 initiator_hmac_; /**< Outgoing (to Bridge) HMAC */
  crypto::HmacSha256 responder_hmac_; /**< Incoming (from Bridge) HMAC */
  crypto::Aes256Ctr initiator_aes_;   /**< Outgoing (to Bridge) AES-256-CTR */
  crypto::Aes256Ctr responder_aes_;   /**< Incoming (from Bridge) AES-256-CTR */
  /** @} */

  /** @{ */
  ProbDist packet_len_rng_;     /**< Packet length morpher */
#ifdef ENABLE_SCRAMBLESUIT_IAT
  ProbDist packet_int_rng_;     /**< Packet interval morpher */
  struct event* iat_timer_ev_;  /**< Packet interval TX event */
#endif
  /** @} */

  /** @{ */
  /** Frame decode state */
  enum class FrameDecodeState {
    kREAD_HEADER,   /**< Reading the header */
    kREAD_PAYLOAD,  /**< Reading the payload */
  } decode_state_;  /**< The frame decoder state */
  /** Frame decode buffer */
  ::std::array<uint8_t, kHeaderLength + kMaxPayloadLength> decode_buf_;
  /** The amount of data in decode_buf_ */
  size_t decode_buf_len_;
  /** The total non-header data in frame being decoded */
  uint16_t decode_total_len_;
  /** The total payload in the frame being decoded */
  uint16_t decode_payload_len_;
  /** @} */

  /** @{ */
  friend SessionTicketHandshake;
  friend UniformDHHandshake;
  /** @} */
};

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied

#endif // SCHWANENLIED_PT_SCRAMBLESUIT_CLIENT_H__
