/**
 * @file    session_ticket_handshake.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit Session Ticket Handshake (IMPLEMENTATION)
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

#include <event2/buffer.h>
#include <event2/util.h>

#include <array>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "schwanenlied/socks5_server.h"
#include "schwanenlied/crypto/base32.h"
#include "schwanenlied/pt/scramblesuit/client.h"
#include "schwanenlied/pt/scramblesuit/session_ticket_handshake.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

using TicketStore = SessionTicketHandshake::TicketStore;
using Ticket = SessionTicketHandshake::Ticket;

constexpr char TicketStore::kTicketFileName[];

bool SessionTicketHandshake::send_handshake_msg(bool& is_done) {
  if (client_.outgoing_ == nullptr)
    return false;
  struct bufferevent* sink = client_.outgoing_;
  is_done = false;

  // Query the store for a ticket associated with the address
  ::std::unique_ptr<Ticket> ticket(store_.get(addr_, addr_len_));
  if (ticket == nullptr)
    return true;

  /*
   * Session Ticket handshake:
   *
   * T | P_C | M_C | MAC(T | P_C | E)
   *
   * T -> The Session Ticket
   * P_C -> Padding [0 - 1388] bytes
   * M_C = HMAC-SHA256-128(k_t, T)
   * MAC = HMAC-SHA256-128(k_t, T | P_C | M_C | E)
   *
   * Spec says k_t is used for the HMACs, but in reality it is the result of the
   * kdf.
   */

  auto t = ticket->ticket();

  if (!client_.kdf_scramblesuit(ticket->key()))
    return false;

  if (!client_.initiator_hmac_.init())
    return false;

  if (!client_.initiator_hmac_.update(t.data(), t.size()))
    return false;

  // Generate M_C
  ::std::array<uint8_t, kDigestLength> m_c;
  if (!client_.initiator_hmac_.digest(t.data(), t.size(), m_c.data(), m_c.size()))
    return false;

  // Generate P_C
  ::std::array<uint8_t, kMaxPadding> p_c;
  const auto padlen = pad_dist_(rand_);
  SL_ASSERT(padlen <= kMaxPadding);
  if (padlen > 0) {
    if (!rand_.get_bytes(p_c.data(), padlen))
      return false;
    if (!client_.initiator_hmac_.update(p_c.data(), padlen))
      return false;
  }

  // The spec doesn't include M_C in the mac, but the code does
  if (!client_.initiator_hmac_.update(m_c.data(), m_c.size()))
      return false;

  // Generate the MAC
  const auto epoch_hour = to_string(::std::time(nullptr) / 3600);
  if (!client_.initiator_hmac_.update(
          reinterpret_cast<const uint8_t*>(epoch_hour.data()),
          epoch_hour.size()))
    return false;
  ::std::array<uint8_t, kDigestLength> mac_c;
  if (!client_.initiator_hmac_.final(mac_c.data(), mac_c.size()))
    return false;

  // Send the message out
  if (0 != ::bufferevent_write(sink, t.data(), t.size()))
    return false;
  if (padlen > 0)
    if (0 != ::bufferevent_write(sink, p_c.data(), padlen))
      return false;
  if (0 != ::bufferevent_write(sink, m_c.data(), m_c.size()))
    return false;
  if (0 != ::bufferevent_write(sink, mac_c.data(), mac_c.size()))
    return false;

  // All done.  (KDF done early because the MAC uses the derived key)
  is_done = true;

  return true;
}

::std::string Ticket::to_string() const {
  const crypto::SecureBuffer blob(key_ + ticket_);

  const auto blob_encoded = crypto::Base32::encode(blob.data(), blob.size());
  return ::std::string(reinterpret_cast<const char*>(blob_encoded.data()),
                       blob_encoded.size());
}

Ticket* TicketStore::get(const struct sockaddr* addr,
                         const socklen_t addr_len) {
  auto iter = tickets_.find(Socks5Server::addr_to_string(addr, false));
  if (iter == tickets_.end())
    return nullptr;

  // Remove the ticket from the store, checkpoint, and return
  Ticket* ret = iter->second;
  tickets_.erase(iter);
  save_tickets();

  return ret;
}

void TicketStore::set(const struct sockaddr* addr,
                      const socklen_t addr_len,
                      const uint8_t* buf,
                      const size_t len,
                      const bool do_write) {
  // Enforce uniqueness
  const auto key = Socks5Server::addr_to_string(addr, false);
  auto iter = tickets_.find(key);
  if (iter != tickets_.end())
    return;

  if (len == Ticket::kKeyLength + Ticket::kTicketLength) {
    tickets_[key] = new Ticket(buf, len);
    if (do_write)
      save_tickets();
  }
}

void TicketStore::load_tickets(const ::std::string& state_dir) {
  // Only attempt to load the ticket backing store once
  if (state_dir_.compare(state_dir) == 0)
    return;
  state_dir_.assign(state_dir);

  // Open the ticket file
  ::std::ifstream ifs(state_dir + kTicketFileName);
  if (!ifs.is_open())
    return;

  // Read the file line by line
  for (::std::string line; ::std::getline(ifs, line); ) {
    // Skip comments
    if ('#' == line.front())
      continue;

    // Expected format is "<address> <Base32 encoded key + ticket>"
    ::std::istringstream iss(line);
    ::std::string addr_str;
    ::std::string blob_base32;
    if (!(iss >> addr_str >> blob_base32))
      continue;

    struct sockaddr_storage addr;
    int addr_len = sizeof(addr);
    if (0 != ::evutil_parse_sockaddr_port(addr_str.c_str(),
                                          reinterpret_cast<struct sockaddr*>(&addr),
                                          &addr_len))
      continue;

    crypto::SecureBuffer blob;
    const size_t len = crypto::Base32::decode(reinterpret_cast<const uint8_t*>(blob_base32.data()),
                                              blob_base32.size(), blob);
    if (Ticket::kKeyLength + Ticket::kTicketLength != len)
      continue;

    set(reinterpret_cast<struct sockaddr*>(&addr),
        static_cast<socklen_t>(addr_len),
        blob.data(), blob.size(), false);
  }
}

void TicketStore::save_tickets() {
  // Open the ticket file
  ::std::ofstream ofs(state_dir_ + kTicketFileName);
  if (!ofs.is_open())
    return;

  // Append a nice banner
  ofs << "#" << ::std::endl
      << "# obfsclient-tickets.txt - ScrambleSuit Session Tickets" << ::std::endl
      << "#" << ::std::endl;

  // Write out all the tickets to disk
  for (const auto& iter : tickets_)
    ofs << iter.first << " " << iter.second->to_string() << ::std::endl;
}

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied
