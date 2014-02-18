/**
 * @file    common.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Common definitions and includes
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

#ifndef SCHWANENLIED_COMMON_H__
#define SCHWANENLIED_COMMON_H__

#include <cstddef>
#include <cstdint>
#include <iostream>

#define _ELPP_STOP_ON_FIRST_ASSERTION
#define _ELPP_NO_DEFAULT_LOG_FILE
#define _ELPP_DISABLE_VMODULES_EXTENSION
#define _ELPP_DISABLE_DEFAULT_CRASH_HANDLING
#include "ext/easylogging++.h"

/**
 * An assert() replacement that will unconditionally be called
 *
 * When the library asserts, it is for something totally fundemental that's a
 * programmer error or the code is in such a messed up state that the only sane
 * thing to do is to exit.  This is used in lieu of throwing exceptions to catch
 * invalid parameters in constructors and thus requires a custom definiton that
 * will be evaluated regardless of NDEBUG being defined.
 */
#define SL_ASSERT(expression)                                           \
do {                                                                    \
  if (!(expression)) {                                                  \
    std::cerr << "Assertion failed: " << #expression << std::endl;      \
    std::cerr << "  in: " << __PRETTY_FUNCTION__ << std::endl;          \
    std::cerr << "  at: " << __FILE__ << ":" << __LINE__ << std::endl;  \
    std::terminate();                                                   \
  }                                                                     \
} while(0)

/**
 * An assert(0) replacement that will give more useful information
 *
 * This is for things like code that should never be reached.
 */
#define SL_ABORT(message)                                               \
do {                                                                    \
  std::cerr << "Internal Error: " << #message << std::endl;             \
  std::cerr << "  in: " << __PRETTY_FUNCTION__ << std::endl;            \
  std::cerr << "  at: " << __FILE__ << ":" << __LINE__ << std::endl;    \
  std::terminate();                                                     \
} while(0)

#ifdef DOXYGEN
/*
 * Doxygen related stuff
 */
/** schwanenlied.me */
namespace schwanenlied {

/** Cryptography modules */
namespace crypto {}

/** Tor Pluggable Transport modules */
namespace pt {}

} // namespace schwanenlied
#endif // DOXYGEN

#endif // SCHWANENLIED_COMMON_H__
