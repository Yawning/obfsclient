/**
 * @file    prob_dist.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit Probability Distribution
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

#ifndef SCHWANENLIED_PT_SCRAMBLESUIT_PROB_DIST_H__
#define SCHWANENLIED_PT_SCRAMBLESUIT_PROB_DIST_H__

#include <random>
#include <string>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/rand_ctr_drbg.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

/**
 * ScrambleSuit Probability Distribution
 *
 * This implements the ScrambleSuit probability distribution based on
 * the C++11 numerics library std::discrete_distribution class.
 */
class ProbDist {
 public:
  /**
   * Construct a new ProbDist instance
   *
   * @param[in] sample_min  The mimimum value that sampling should return
   * @param[in] sample_max  The maximum value that sampling should return
   */
  ProbDist(const uint32_t sample_min,
           const uint32_t sample_max) :
      bucket_dist_(kMinBuckets, kMaxBuckets),
      weight_dist_(0, 100) {
    reset(nullptr, 0, sample_min, sample_max);
  }

  ~ProbDist() = default;

  /**
   * Reseed then PRNG and regenerate the outcomes/probabilities
   *
   * If seed is nullptr or 0 length, the PRNG is left intact, however the
   * distribution will always be re-initialized.
   *
   * @param[in] seed        The new seed for the PRNG
   * @param[in] seed_len    The length of the new PRNG seed
   * @param[in] sample_min  The mimimum value that sampling should return
   * @param[in] sample_max  The maximum value that sampling should return
   */
  void reset(const uint8_t* seed,
             const size_t seed_len,
             const uint32_t sample_min,
             const uint32_t sample_max);

  /**
   * Sample the distribution
   *
   * @returns A value between sample_min/sample_max (inclusive) passed to the
   * constructor/reset()
   */
  uint32_t operator()() {
    return values_.at(prob_dist_(rng_));
  }

  /** Dump the probability table for logging (Verbose) */
  const ::std::string to_string() const;

 private:
  ProbDist() = delete;
  ProbDist(const ProbDist&) = delete;
  void operator=(const ProbDist&) = delete;

  /** The minimum number of buckets */
  static constexpr size_t kMinBuckets = 1;
  /** The maximum number of buckets */
  static constexpr size_t kMaxBuckets = 100;

  /** The uniform distribution for generating the number of buckets */
  ::std::uniform_int_distribution<int> bucket_dist_;
  /** The uniform distribution for generating the probabilities */
  ::std::uniform_int_distribution<int> weight_dist_;

  /** The CTR_DRBG-AES-128 PRNG */
  crypto::RandCtrDrbg rng_;
  /** The possible outcomes */
  ::std::vector<uint32_t> values_;
  /** The weighted distribution used to return a value */
  ::std::discrete_distribution<int> prob_dist_;
};

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied

#endif // SCHWANENLIED_PT_SCRAMBLESUIT_PROB_DIST_H__
