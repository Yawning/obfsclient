/**
 * @file    socks5_server.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SOCKSv5 Server
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

#ifndef SCHWANENLIED_SOCKS5_SERVER_H__
#define SCHWANENLIED_SOCKS5_SERVER_H__

#include <list>
#include <memory>

#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "schwanenlied/common.h"

namespace schwanenlied {

/**
 * A simple libevent2 based SOCKSv5 server
 *
 * This is used by subclassing Session and SessionFactory with the desired
 * behavior.  In general SessionFactory should be a simple adapter to create a
 * new Session instance.  Some familiarity with libevent2 is assumed.
 *
 * Socks5Server will handle:
 *  * The SOCKSv5 protocol
 *  * Opening a TCP/IP connection to the remote peer
 *  * Attempting to flush queued data when either of the connections is closed
 *
 * Current limitations:
 *  * It will *ALWAYS* bind to 127.0.0.1:RandomPort
 *  * Only CONNECT (establish TCP/IP stream) is supported
 *  * Only ATYP 0x01/0x03 are supported (no FQDN)
 *  * GSSAPI auth will never be supported
 *
 * @warning Destroying the Socks5Server instance (or calling
 * Socks5Server::close()) **WILL NOT** terminate existing sessions.
 */
class Socks5Server {
 public:
  /**
   * The SOCKSv5 session
   *
   * All servers *MUST* implement this class to provide desired behavior.  In
   * the simple case (where transforming data is not required), it is sufficient
   * to call send_socks5_response() from the on_outgoing_connected() callback,
   * and shuffle data between incoming_ and outgoing_ in
   * incoming_read_cb()/outgoing_read_cb().  When it is neccecary to terminate a
   * session, deleting the instance will do the right thing.
   */
  class Session {
   public:
    /**
     * Construct a Session instance
     *
     * @param[in] base          The libevent2 event_base associated with the
     *                          Socks5Server
     * @param[in] sock          The Client to SOCKS server socket
     * @param[in] addr          The address of the client
     * @param[in] addr_len      The length of the sockaddr pointed to by addr
     * @param[in] require_auth  Authentication is required?
     */
    Session(struct event_base* base,
            const evutil_socket_t sock,
            const struct sockaddr* addr,
            const int addr_len,
            const bool require_auth = false);

    virtual ~Session();

   protected:
    /** The SOCKSv5 reply codes */
    enum Reply {
      kSUCCEDED = 0x00,             /**< Succeded */
      kGENERAL_FAILURE = 0x01,      /**< General SOCKS server failure */
      kNOT_ALLOWED = 0x02,          /**< Connection not allowed */
      kNETWORK_UNREACHABLE = 0x03,  /**< Network unreachable */
      kHOST_UNREACHABLE = 0x04,     /**< Host unreachable */
      kCONNECTION_REFUSED = 0x05,   /**< Connection refused */
      kTTL_EXPIRED = 0x06,          /**< TTL expired */
      kCOMMAND_NOT_SUPP = 0x07,     /**< Command not supported */
      kADDR_NOT_SUPP = 0x08         /**< Address type not supported */
    };

    /** @{ */
    /**
     * Client authentication callback
     *
     * Called when the client authenticates with the SOCKS server, but before
     * the connect request comes in.  It is important to note that neither uname
     * nor passwd are NULL terminated, and returning false from this routine
     * will terminate the session.
     *
     * @param[in] uname   Username
     * @param[in] ulen    The length of uname
     * @param[in] passwd  Password
     * @param[in] plen    The length of password
     *
     * @returns true  - Success
     * @returns false - Failure (Close connection)
     */
    virtual bool on_client_authenticate(const uint8_t* uname,
                                        const uint8_t ulen,
                                        const uint8_t* passwd,
                                        const uint8_t plen) {
      return false;
    }

    /** Remote peer connection established callback */
    virtual void on_outgoing_connected() = 0;

    /** Client to SOCKS Server data received callback */
    virtual void on_incoming_data() = 0;

    /** SOCKS Server to Client write queue empty callback */
    virtual void on_incoming_drained() {}

    /** Client to SOCKS Server data received callback (State::kCONNECTING) */
    virtual void on_outgoing_data_connecting() = 0;

    /** Remote peer to SOCKS Server data received callback */
    virtual void on_outgoing_data() = 0;

    /** SOCKS Server to Remote peer write queue empty callback */
    virtual void on_outgoing_drained() {}
    /** @} */

    /**
     * Send a SOCKSv5 response to the client
     *
     * This should be called when the remote connection is established and the
     * session is ready to start relaying data.
     *
     * @note Sending a failure message will cause the current session to be
     * destroyed after the response is sent.
     *
     * @warning On certain libevent failures, this routine will destroy the
     * session, so after invoking this, it is UNSAFE to touch the session for
     * the remainer of the callback.
     *
     * @param[in] reply The reply code to be sent
     */
    void send_socks5_response(const Reply reply);

    /** The libevent2 event_base */
    struct event_base* base_;
    /** The Client to SOCKS Server bufferevent */
    struct bufferevent* incoming_;
    /** The SOCKS Server to Remote peer bufferevent */
    struct bufferevent* outgoing_;
    /** The remote peer's address */
    struct sockaddr_storage remote_addr_;
    /** The length of remote_addr_ */
    socklen_t remote_addr_len_;

    /** The SOCKSv5 session state */
    enum class State {
      kINVALID,
      kREAD_METHODS,      /**< Reading auth methods */
      kAUTHENTICATING,    /**< Authenticating (Optional) */
      kREAD_REQUEST,      /**< Reading request */
      kCONNECTING,        /**< Connecting to remote destination */
      kESTABLISHED,       /**< Established, proxying data */
      kFLUSHING_INCOMING, /**< outgoing_ closed, flushing incoming_ */
      kFLUSHING_OUTGOING, /**< incoming_ closed, flushing outgoing_ */
    } state_; /**< The SOCKSv5 session state */

   private:
    Session(const Session&) = delete;
    void operator=(const Session&) = delete;

    static const uint8_t kSocksVersion = 0x05;

    /** The SOCKSv5 authentication methods */
    enum AuthMethod {
      kNONE_REQUIRED = 0x00,      /**< NO AUTHENTICATION RQUIRED */
      kGSSAPI = 0x01,             /**< GSSAPI (Unsupported) */
      kUSERNAME_PASSWORD = 0x02,  /**< USERNAME/PASSWORD (RFC1929) */
      kTOR_EXTENDED = 0x80,       /**< Tor Pluggable Transport (EXPERIMENTAL) */
      kNO_ACCEPTABLE = 0xff       /**< NO ACCEPTABLE METHODS */
    };

    /** The SOCKSv5 command types */
    enum Command {
      kCONNECT = 0x01,      /**< TCP/IP Connect */
      kBIND = 0x02,         /**< TCP/IP Bind (Unsupported) */
      kUDP_ASSOCIATE = 0x03 /**< UDP bind (Unsupported) */
    };

    /** The SOCKSv5 address types */
    enum AddressType {
      kIPv4 = 0x01,       /**< IPv4 */
      kDOMAINNAME = 0x02, /**< FQDN (Unsupported) */
      kIPv6 = 0x04        /**< IPv6 */
    };

    bool auth_required_;  /**< Client must authenticate? */
    AuthMethod auth_method_; /**< Negotiated auth method */
    bool incoming_valid_; /**< incoming_ connected? */
    bool outgoing_valid_; /**< outgoing_ connected? */

    /** @{ */
    /** The Client to SOCKS server libevent2 bufferevent read callback */
    void incoming_read_cb();

    /** The State::kREAD_METHODS read callback */
    void incoming_read_methods_cb();

    /** The State::kAUTHENTICATING read callback */
    void incoming_read_auth_cb();

    /** The State::kREAD_REQUEST read callback */
    void incoming_read_request_cb();

    /** The SOCKS server to Client libevent2 bufferevent write callback */
    void incoming_write_cb();

    /** The Client to SOCKS server socket bufferevent event callback */
    void incoming_event_cb(const short events);

    /** The Remote peer to SOCKS server libevent2 bufferevent read callback */
    void outgoing_read_cb();

    /** The SOCKS server to Remote peer libevent2 bufferevent write callback */
    void outgoing_write_cb();

    /** The SOCKS server to Remote peer socket bufferevent event callback */
    void outgoing_event_cb(const short events);
    /** @} */

    /** @{ */
    /**
     * Open a TCP/IP connection to remote_addr_
     *
     * @returns true  - Success
     * @returns false - Failure
     */
    bool outgoing_connect();
    /** @} */
  };

  /**
   * Session Factory
   *
   * A factory is used to create Session instances of the appropriate type when
   * a client session is established.
   */
  class SessionFactory {
   public:
    virtual ~SessionFactory() = default;

    /**
     * Create a new Session instance
     *
     * @param[in] base      The libevent2 event_base associated with the
     *                      Socks5Server
     * @param[in] sock      The Client to SOCKS server socket
     * @param[in] addr      The address of the client
     * @param[in] addr_len  The length of the sockaddr pointed to by addr
     *
     * @returns A pointer to a valid Session instance
     * @returns nullptr - Session initialization failed (caller will close sock)
     */
    virtual Session* create_session(struct event_base* base,
                                    const evutil_socket_t sock,
                                    const struct sockaddr* addr,
                                    const int addr_len) = 0;
  };

  /**
   * Construct a Socks5Server
   *
   * @param[in] factory   The SessionFactory to use when creating Session
   *                      instances for client connections
   * @param[in] base      The libevent2 event_base to use
   */
  Socks5Server(SessionFactory* factory,
               struct event_base* base) :
      factory_(factory),
      base_(base),
      listener_(nullptr),
      listener_addr_() {}

  ~Socks5Server();

  /** @{ */
  /**
   * Query the local address that the Socks5Server is listening on
   *
   * @param[out]  addr  The address to fill with the local address
   *
   * @returns true  - The Socks5Server is listening
   * @returns false - The Socks5Server is not listening (Call bind())
   */
  const bool addr(struct sockaddr_in& addr) const;
  /** @} */

  /** @{ */
  /**
   * Bind to a socket on the loopback interface
   *
   * @returns true  - Bound and ready to accept connections
   * @returns false - Failed to bind to a socket
   */
  bool bind();

  /**
   * Close the SOCKS server socket
   *
   * @warning Existing sessions are unaffected
   */
  void close();
  /** @} */

 private:
  Socks5Server(const Socks5Server&) = delete;
  void operator=(const Socks5Server&) = delete;

  /** The SOCKS server libevent2 evconnlistener callback */
  void on_new_connection(evutil_socket_t sock,
                         struct sockaddr* addr,
                         int len);

  SessionFactory* factory_;   /**< The factory used to create Sessions */
  struct event_base* base_;   /**< The libevent2 event_base */
  struct evconnlistener* listener_;   /**< The SOCKS server socket */
  struct sockaddr_in listener_addr_;  /**< The SOCKS server socket address */
};

} // namespace schwanenlied

#endif // SCHWANENLIED_SOCKS5_SERVER_H__
