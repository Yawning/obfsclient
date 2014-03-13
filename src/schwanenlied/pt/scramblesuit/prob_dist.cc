/**
 * @file    prob_dist.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit Probability Distribution (IMPLEMENTATION)
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

#include <algorithm>
#include <sstream>

#include "schwanenlied/pt/scramblesuit/prob_dist.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

void ProbDist::reset(const uint8_t* seed,
                     const size_t seed_len,
                     const uint32_t sample_min,
                     const uint32_t sample_max) {
  SL_ASSERT(sample_max - sample_min > 0);

  // Optionally reseed the PRNG
  if (seed != nullptr && seed_len > 0) {
    rng_.seed(seed, seed_len);
    bucket_dist_.reset();
  }

  const size_t range = sample_max - sample_min;

  // Generate the values
  values_.resize(range);
  for (size_t i = 0; i < range; i++)
    values_.at(i) = sample_min + i;
  ::std::shuffle(values_.begin(), values_.end(), rng_);

  // Calculate the number of buckets
  const size_t n = ::std::min<size_t>(bucket_dist_(rng_), range);
  values_.resize(n);

  // Generate weights
  int to_distribute = 10000;  // 0.0001 granularity
  ::std::vector<int> weights(values_.size());
  for (int& val : weights) {
    ::std::uniform_int_distribution<int> dist(0, to_distribute);
    int weight = dist(rng_);
    to_distribute -= weight;
    val = weight;
    if (to_distribute == 0)
      break;
  }
  weights.at(weights.size() - 1) += to_distribute;

  // Setup the discrete distribution
  typedef ::std::discrete_distribution<>::param_type param_type;
  prob_dist_.param(param_type(weights.begin(), weights.end()));

  // Reseed since, the part that needs to be deterministic is over
  rng_.seed();
}

const ::std::string ProbDist::to_string() const {
  const auto probs = prob_dist_.probabilities();
  ::std::ostringstream stream;

  for (size_t i = 0; i < values_.size(); i++) {
    // Skip buckets with probability 0
    if (probs.at(i) != 0.0d)
      stream << ' ' << values_.at(i) << ": " << probs.at(i) << ' ';
  }

  return stream.str();
}

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied
