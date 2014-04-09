/**
 * @file    ctr.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Block cipher counter (CTR) mode
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

#ifndef SCHWANENLIED_CRYPTO_CTR_H__
#define SCHWANENLIED_CRYPTO_CTR_H__

#include <cstring>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * Generic ECB based CTR mode
 *
 * Given a block cipher that can encrypt a block via ECB mode, implement counter
 * mode.
 */
template <class T>
class Ctr {
 public:
  /**
   * Create a Ctr mode instance
   */
  Ctr() :
      has_state_(false),
      iv_size_(0),
      ctr_(ecb_impl_.block_length(), 0),
      block_(ecb_impl_.block_length(), 0),
      offset_(0) {}

  ~Ctr() = default;

  /** @{ */
  /**
   * Initialize the key, initialization vector, and counter
   *
   * Initialization vector in this context is the fixed prefix (if any) that
   * will be inserted in front of the counter.  Naturally, iv_len + ctr_len
   * *MUST* equal the block cipher's block size.
   *
   * @param[in] key     The key to use (must be the appropriate length)
   * @param[in] iv      A pointer to the counter prefix if any (can be nullptr)
   * @param[in] iv_len  The length of the prefix
   * @param[in] ctr     A pointer to the initial counter
   * @param[in] ctr_len The length of the initial counter
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool set_state(const SecureBuffer& key,
                 const uint8_t* iv,
                 const size_t iv_len,
                 const uint8_t* ctr,
                 const size_t ctr_len) {
    if (key.size() != ecb_impl_.key_length())
      return false;
    if (ctr == nullptr)
      return false;
    if (ctr_len == 0)
      return false;
    if (ctr_len + iv_len != ecb_impl_.block_length())
      return false;

    clear_state();

    if (!ecb_impl_.set_key(key))
      return false;

    iv_size_ = iv_len;
    ::std::memcpy(&ctr_[0], iv, iv_len);
    ::std::memcpy(&ctr_[iv_len], ctr, ctr_len);

    has_state_ = true;

    return true;
  }

  /**
   * Destroy the current state
   */
  void clear_state() {
    if (has_state_) {
      ecb_impl_.clear_key();
      ::std::fill(ctr_.begin(), ctr_.end(), 0);
      ::std::fill(block_.begin(), block_.end(), 0);
      offset_ = 0;
      has_state_ = false;
    }
  }

  /**
   * Is the state initialized?
   */
  bool has_state() const { return has_state_; }
  /** @} */

  /**
   * Encrypt/Decrypt
   *
   * As CTR mode does the exact same thing when encrypting and decrypting, only
   * one routine is provided to handle both.
   *
   * @param[in]   buf The data to encrypt/decrypt
   * @param[in]   len The size of the data to encrypt/decrypt
   * @param[out]  out A buffer for the processed data
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool process(const uint8_t* buf,
               const size_t len,
               uint8_t* out) {
    if (buf == nullptr && len != 0)
      return false;
    if (out == nullptr && len != 0)
      return false;
    if (!has_state_)
      return false;

    for (size_t i = len; i > 0; i--) {
      // If the offset is 0, this means that the block stored is empty.
      if (offset_ == 0) {
        // Generate a new block
        if (!ecb_impl_.encrypt_block(ctr_.data(), block_.size(), &block_[0]))
          return false;

        // Increment ctr_ (which always stores the next value to be used)
        for (auto j = ctr_.rbegin(); j != ctr_.rend() - iv_size_; ++j)
          if (++*j != 0)
            break;
      }

      *out++ = (*buf++) ^ block_[offset_];
      offset_ = (offset_ + 1) % ecb_impl_.block_length();
    }

    return true;
  }

 private:
  Ctr(const Ctr&) = delete;
  void operator=(const Ctr&) = delete;

  bool has_state_;      /**< Is the internal state initialized? */
  T ecb_impl_;          /**< The underlying block cipher instance */
  size_t iv_size_;      /**< The length of the fixed counter prefix */
  SecureBuffer ctr_;    /**< The prefix + counter */
  SecureBuffer block_;  /**< The ECB encryted ctr_ */
  size_t offset_;       /**< The offset into the counter */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_CTR_H__
