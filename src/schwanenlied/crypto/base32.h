/**
 * @file    base32.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Base32 Decoder
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

#ifndef SCHWANENLIED_CRYPTO_BASE32_H__
#define SCHWANENLIED_CRYPTO_BASE32_H__

#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * A Base32 decoder
 *
 * A simple Base32 decoder based off the "Public Domain" bitpedia Java code
 * (Project died, but the source is available
 * [here](http://bitcollider.cvs.sourceforge.net/viewvc/bitcollider/jbitcollider/plugins/org.bitpedia.collider.core/src/org/bitpedia/util/Base32.java?revision=1.2&view=markup)).
 * The original implementation uses a lookup table, but doing the alphabet
 * calcuation is easy so this implementation does that instead.
 */
namespace Base32 {

/**
 * Decode a Base32 buffer
 *
 * @param[in] buf   The buffer to decode
 * @param[in] len   The length of the buffer to decode
 * @param[out] dst  The buffer for the decoded output
 *
 * @returns The lenght of the decoded output
 */
size_t decode(const uint8_t* buf,
              const size_t len,
              SecureBuffer& dst);
} // namespace Base32

} // namespace crpto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_BASE32_H__
