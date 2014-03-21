/**
 * @file    obfs2/client.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   obfs2 (The Twobfuscator) Client
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

#ifndef SCHWANENLIED_PT_OBFS2_CLIENT_H__
#define SCHWANENLIED_PT_OBFS2_CLIENT_H__

#define OBFS2_LOGGER "obfs2"
#ifdef OBFS2_CLIENT_IMPL
#define _LOGGER OBFS2_LOGGER
#endif

#include <random>

#include "schwanenlied/common.h"
#include "schwanenlied/socks5_server.h"
#include "schwanenlied/crypto/aes.h"
#include "schwanenlied/crypto/rand_openssl.h"
#include "schwanenlied/crypto/sha256.h"

namespace schwanenlied {
namespace pt {

/** obfs2 (The Twobfuscator) */
namespace obfs2 {

/**
 * obfs2 (The Twobfuscator) Client
 *
 * This implements a wire compatibile obfs2 client using Socks5Server.
 *
 * @todo Investigate using evbuffer_peek()/evbuffer_add_buffer() for better
 * performance (current code is more obviously correct).
 */
class Client : public Socks5Server::Session {
 public:
  /** Client factory */
  class SessionFactory : public Socks5Server::SessionFactory {
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
      Session(server, base, sock, addr, false, scrub_addrs),
      logger_(::el::Loggers::getLogger(OBFS2_LOGGER)),
      received_seed_hdr_(false),
      resp_pad_len_(0),
      init_seed_(kSeedLength, 0),
      resp_seed_(kSeedLength, 0),
      pad_dist_(0, kMaxPadding) {}

  ~Client() = default;

 protected:
  void on_outgoing_connected() override;

  void on_incoming_data() override;

  void on_outgoing_data_connecting() override;

  void on_outgoing_data() override;

 private:
  Client(const Client&) = delete;
  void operator=(const Client&) = delete;

  /** @{ */
  static constexpr uint32_t kMagicValue = 0x2BF5CA7E; /**< obfs2 MAGIC_VALUE */
  static constexpr size_t kSeedLength = 16;           /**< obfs2 SEED_LENGTH */
  static constexpr size_t kMaxPadding = 8192;         /**< obfs2 MAX_PADDING */
  /** @} */

  /** @{ */
  /**
   * Implement MAC(s, x) per the obfs2 spec
   *
   * @param[in] key     The key for the MAC ("s")
   * @param[in] key_len The length of the key
   * @param[in] buf     The buffer to be MACed ("x")
   * @param[in] len     The length of the buffer to be MACed
   * @param[out] digest A crypto::SecureBuffer where the digest should be stored
   *
   * @returns true - Success
   * @returns false - Failure
   */
  bool mac(const uint8_t* key,
           const size_t key_len,
           const uint8_t* buf,
           const size_t len,
           crypto::SecureBuffer& digest);

  /**
   * Given init_seed_ and resp_seed_, derive the AES-CTR-128 keys per the obfs2
   * spec
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool kdf_obfs2();
  /** @} */

  ::el::Logger* logger_;            /**< The obfs2 session logger */

  /** @{ */
  crypto::Aes128Ctr initiator_aes_; /**< Initiator->Responder E(K,s) */
  crypto::Aes128Ctr responder_aes_; /**< Responder->Initiator E(K,s) */
  crypto::RandOpenSSL rand_;        /**< CSPRNG */
  /** @} */

  /** @{ */
  bool received_seed_hdr_;          /**< Recived the peer's seed, magic, padlen? */
  size_t resp_pad_len_;             /**< Amount of padding to discard */
  crypto::SecureBuffer init_seed_;  /**< obfs2 INIT_SEED */
  crypto::SecureBuffer resp_seed_;  /**< obfs2 RESP_SEED */
  ::std::uniform_int_distribution<uint32_t> pad_dist_;  /** Padding distribution */
  /** @} */
};

} // namespace obfs2
} // namespace pt
} // namespace schwanenlied

#endif // SCHWANENLIED_PT_OBFS2_CLIENT_H__
