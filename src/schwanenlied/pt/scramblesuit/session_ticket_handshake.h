/**
 * @file    session_ticket_handshake.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit Session Ticket Handshake
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

#ifndef SCHWANENLIED_PT_SCRAMBLESUIT_SESSION_TICKET_H__
#define SCHWANENLIED_PT_SCRAMBLESUIT_SESSION_TICKET_H__

#include <netinet/in.h>

#include <map>
#include <random>
#include <string>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/rand_openssl.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

class Client;

/**
 * Implement the client side of the ScrambleSuit Session Ticket Handshake
 */
class SessionTicketHandshake {
 public:
  /**
   * A Session Ticket
   */
  class Ticket {
   public:
    static constexpr size_t kKeyLength = 32;      /**< k_t length */
    static constexpr size_t kTicketLength = 112;  /**< T length */

    /**
     * Create a new Ticket given k_t | T
     *
     * @param[in] buf   The buffer containing k_t | T
     * @param[in] len   The length of buf (Must be kKeyLength + kTicketLength)
     */
    Ticket(const uint8_t* buf,
           const size_t len) {
      SL_ASSERT(len == kKeyLength + kTicketLength);
      key_.assign(buf, kKeyLength);
      ticket_.assign(buf + kKeyLength, kTicketLength);
    }

    ~Ticket() = default;

    /** Return the k_t */
    const crypto::SecureBuffer& key() const { return key_; }

    /** Return the ticket */
    const crypto::SecureBuffer& ticket() const { return ticket_; }

    /** Encode k_t | T via Base32 */
    ::std::string to_string() const;

   private:
    Ticket() = delete;
    Ticket(const Ticket&) = delete;
    void operator=(const Ticket&) = delete;

    crypto::SecureBuffer key_;    /**< k_t */
    crypto::SecureBuffer ticket_; /**< The ticket */
  };

  /**
   * The ticket store for persisting tickets to disk (singleton)
   *
   * @warning This is not and will never be thread safe
   *
   * @bug If multiple tickets that belong to peers that are not accessed via
   * IPv4 or IPV6 are entered at once.
   * @bug This leaks the tickets in the ticket store when the dtor is called,
   * not a huge problem as that only happens on application termination.
   */
  class TicketStore {
   public:
    /**
     * Obtain the TicketStore singleton instance
     *
     * Passing in a different state_dir will cause the instance to reload the
     * ticket file from the new directory, but that behavior is untested and
     * unsupported.
     *:
     *
     * @param[in] state_dir   The directory to look for the ticket file
     *
     * @returns The TicketStore singleton instance
     */
    static TicketStore& get_instance(const ::std::string& state_dir) {
      static TicketStore instance;
      instance.load_tickets(state_dir);

      return instance;
    }

    /**
     * Given an address, remove the peer's ticket from the store and return it
     *
     * @warning Caller must clean up the ticket
     *
     * @param[in] addr      The address/port of the remote peer
     * @param[in] addr_len  The length of addr
     *
     * @returns The ticket if it exists, nullptr otherwise
     */
    Ticket* get(const struct sockaddr* addr,
                const socklen_t addr_len);

    /**
     * Given an address and a raw key + ticket, store it as a ticket object, and
     * optionally persist it to disk.
     *
     * @param[in] addr      The address/port of the remote peer
     * @param[in] addr_len  The length of addr
     * @param[in] buf       The buffer containing the key/ticket
     * @param[in] len       The length of buf
     * @param[in] do_write  Commit the ticket store to disk
     */
    void set(const struct sockaddr* addr,
             const socklen_t addr_len,
             const uint8_t* buf,
             const size_t len,
             const bool do_write = true);

   private:
    TicketStore() = default;
    ~TicketStore() = default;
    TicketStore(const TicketStore&) = delete;
    void operator=(const TicketStore&) = delete;

    /** The ticket file */
    static constexpr char kTicketFileName[] = "obfsclient-tickets.txt";

    /**
     * Load previously saved tickets from disk
     *
     * @param[in] state_dir   Path to the ticket file
     */
    void load_tickets(const ::std::string& state_dir);

    /** Save the current tickets to disk */
    void save_tickets();

    ::std::string state_dir_; /**< The directory where the tickets live */
    ::std::map< ::std::string, Ticket*> tickets_; /**< The ticket store */
  };

  /**
   * Construct a new SessionTicketHandshake instance
   *
   * @param[in] client    The Client instance
   * @param[in] state_dir Directory where the TicketStore should keep files
   * @param[in] addr      The address/port of the remote peer
   * @param[in] addr_len  The length of addr
   */
  SessionTicketHandshake(Client& client,
                         const ::std::string& state_dir,
                         const struct sockaddr* addr,
                         const socklen_t addr_len) :
      client_(client),
      store_(TicketStore::get_instance(state_dir)),
      addr_(addr),
      addr_len_(addr_len),
      pad_dist_(0, kMaxPadding) {}

  ~SessionTicketHandshake() = default;

  /**
   * Send the outgoing side of the handshake
   *
   * @param[out] is_done  The handshake completed?
   *
   * @returns true  - Success (Check is_done)
   * @returns false - Failure (MUST CLOSE CONNECTION)
   */
  bool send_handshake_msg(bool& is_done);

  /**
   * Handle tickets received from the peer
   *
   * @param[in] buf       The the new key + ticket
   * @param[in] len       The length of the new key + ticket
   */
  void on_new_ticket(const uint8_t* buf,
                     const size_t len) {
    store_.set(addr_, addr_len_, buf, len);
  }

 private:
  SessionTicketHandshake(const SessionTicketHandshake&) = delete;
  void operator=(const SessionTicketHandshake&) = delete;

  /** @{ */
  /** The HMAC-SHA-256 digest length (M, MAC) */
  static constexpr size_t kDigestLength = 16;
  /** The maximum allowed padding length (P_C) */
  static constexpr size_t kMaxPadding = 1388;
  /** @} */

  /** @{ */
  Client& client_; /**< The Client instance the handshake is for */
  TicketStore& store_;              /**< Ticket store */
  const struct sockaddr* addr_;     /**< Remote peer address */
  const socklen_t addr_len_;        /**< Length of addr_ */
  crypto::RandOpenSSL rand_;        /**< CSPRNG */
  ::std::uniform_int_distribution<uint32_t> pad_dist_; /**< Padding distribution */
  /** @} */
};

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied

#endif // SCHWANENLIED_PT_SCRAMBLESUIT_SESSION_TICKET_H__
