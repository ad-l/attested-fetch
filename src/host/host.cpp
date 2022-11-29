// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "afetch_u.h"

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <openenclave/host.h>
#include <vector>

int main(int argc, const char* argv[])
{
  oe_result_t result;
  int ret = 1;
  oe_enclave_t* enclave = NULL;

  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG_AUTO;

  if (argc != 6 && argc != 7)
  {
    std::cerr << "Usage: " << argv[0]
              << " enclave_file issuer feed url nonce [out_file]" << std::endl;
    return 1;
  }

  const char* enclave_file = argv[1];
  const char* issuer = argv[2];
  const char* feed = argv[3];
  const char* url = argv[4];
  const char* nonce = argv[5];

  // Create the enclave
  result = oe_create_afetch_enclave(
    enclave_file, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
  if (result != OE_OK)
  {
    std::cerr << "oe_create_fetch_enclave(): result=" << result << " ("
              << oe_result_str(result) << ")" << std::endl;
    return 1;
  }

  // Call into the enclave
  std::vector<uint8_t> out(10 * 1024 * 1024);
  size_t n;
  result =
    enclave_main(enclave, issuer, feed, url, nonce, out.data(), out.size(), &n);
  if (result != OE_OK)
  {
    std::cerr << "calling into enclave_main failed: result=" << result << " ("
              << oe_result_str(result) << ")" << std::endl;
    return 1;
  }

  oe_terminate_enclave(enclave);

  if (argc == 7)
  {
    const char* out_file = argv[6];
    std::ofstream out_stream(out_file, std::ios::binary);
    out_stream.write((const char*)out.data(), n);
  }
  else
  {
      write(STDOUT_FILENO, out.data(), n);
  }

  return 0;
}
