/**
 * @file    utils.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Cryptography related utility routines
 */

/*
 * Copyright (c) 2013, Yawning Angel <yawning at schwanenlied dot me>
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

#ifndef SCHWANENLIED_CRYPTO_UTILS_H__
#define SCHWANENLIED_CRYPTO_UTILS_H__

#include <memory>
#include <string>

#include "schwanenlied/common.h"

namespace schwanenlied {
namespace crypto {

/**
 * Zero fill a buffer
 *
 * @param[in] s The buffer to wipe
 * @param[in] n The length of the buffer
 * @return A pointer to the start of the wiped buffer
 */
void* memwipe(void* s,
              size_t n);

/**
 * Constant time memory comparison
 *
 * @param[in] s1  The first buffer
 * @param[in] s2  The second buffer
 * @param[in] n   The length of the buffers
 * @return 0 if the buffers are equal, something else if not
 */
int memequals(const void* s1,
              const void* s2,
              const size_t n);

/**
 * A custom allocator that calls memwipe() on deallocate
 */
template<typename T>
class SecureAllocator: public ::std::allocator<T> {
 public:
  SecureAllocator() throw() : ::std::allocator<T>() {}
  SecureAllocator(const SecureAllocator& a) throw() : ::std::allocator<T>(a) {}
  template<typename U>
  SecureAllocator(const SecureAllocator<U>& a) throw() : ::std::allocator<T>(a) {}
  ~SecureAllocator() throw() {}

  /** @cond PRIVATE */
  template<typename _TOther>
  struct rebind {
    typedef SecureAllocator<_TOther> other;
  };
  /** @endcond */

  void deallocate(T* p, ::std::size_t n) {
    if (p != nullptr)
      memwipe(p, sizeof(T) * n);
    ::std::allocator<T>::deallocate(p, n);
  }
};

/** A uint8_t std::string container that  calls memwipe() on deallocate */
typedef ::std::basic_string<uint8_t, ::std::char_traits<uint8_t>,
        SecureAllocator<uint8_t> > SecureBuffer;

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_UTILS_H__
