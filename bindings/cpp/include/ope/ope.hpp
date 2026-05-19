#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include "ope.h"
}

namespace ope {

inline std::string version() { return std::string(ope_version()); }

inline void check(int rc, const char *ctx) {
  if (rc == OPE_OK) {
    return;
  }
  char buf[512];
  ope_last_error_message(buf, sizeof(buf));
  throw std::runtime_error(std::string(ctx) + ": " + buf + " (code " +
                           std::to_string(rc) + ")");
}

class Envelope {
 public:
  static std::string sign(const std::array<uint8_t, OPE_KEY_BYTES> &secret_key,
                          const std::string &json_in) {
    char *out = nullptr;
    int rc = ope_envelope_sign(secret_key.data(), json_in.c_str(), &out);
    if (rc != OPE_OK) {
      check(rc, "ope_envelope_sign");
    }
    std::string result(out);
    ope_string_free(out);
    return result;
  }

  static void verify(const std::array<uint8_t, OPE_KEY_BYTES> &public_key,
                     const std::string &json,
                     uint32_t max_skew_secs = 300) {
    check(ope_envelope_verify(public_key.data(), json.c_str(), max_skew_secs),
          "ope_envelope_verify");
  }
};

}  // namespace ope
