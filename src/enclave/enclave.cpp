// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "afetch_t.h"
#include "curl.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "util.h"

#include <exception>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/enclave.h>
#include <string>
#include <vector>

static constexpr int64_t ATTESTATION_SOURCE_OPENENCLAVE = 1;

struct Quote
{
  std::vector<uint8_t> evidence;
  std::vector<uint8_t> endorsements;
};

Quote get_quote(std::span<const uint8_t> key)
{
  auto sgx_report_data = afetch::sha256(key);

  // Create SGX quote with digest of encoded COSE key
  auto rc = oe_attester_initialize();
  if (rc != OE_OK)
  {
    throw std::logic_error("Failed to initialise evidence attester");
  }

  const size_t custom_claim_length = 1;
  oe_claim_t custom_claim;
  custom_claim.name = const_cast<char*>(OE_CLAIM_SGX_REPORT_DATA);
  custom_claim.value = sgx_report_data.data();
  custom_claim.value_size = sgx_report_data.size();

  uint8_t* serialised_custom_claims_buf = nullptr;
  size_t serialised_custom_claims_size = 0;

  rc = oe_serialize_custom_claims(
    &custom_claim,
    custom_claim_length,
    &serialised_custom_claims_buf,
    &serialised_custom_claims_size);
  if (rc != OE_OK)
  {
    throw std::logic_error("Could not serialise OE custom claim");
  }

  uint8_t* evidence_buf;
  size_t evidence_size;
  uint8_t* endorsements_buf;
  size_t endorsements_size;

  oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};

  rc = oe_get_evidence(
    &oe_quote_format,
    0,
    serialised_custom_claims_buf,
    serialised_custom_claims_size,
    nullptr,
    0,
    &evidence_buf,
    &evidence_size,
    &endorsements_buf,
    &endorsements_size);
  if (rc != OE_OK)
  {
    throw std::logic_error("Failed to get evidence");
  }

  Quote quote = {
    std::vector<uint8_t>(evidence_buf, evidence_buf + evidence_size),
    std::vector<uint8_t>(
      endorsements_buf, endorsements_buf + endorsements_size),
  };

  oe_free_serialized_custom_claims(serialised_custom_claims_buf);
  oe_free_evidence(evidence_buf);
  oe_free_endorsements(endorsements_buf);

  oe_attester_shutdown();

  return quote;
}

void encode_attestation_report(
  QCBOREncodeContext* ctx,
  const Quote& quote,
  std::span<const uint8_t> cose_key)
{
  QCBOREncode_OpenArray(ctx);
  QCBOREncode_AddInt64(ctx, ATTESTATION_SOURCE_OPENENCLAVE);
  QCBOREncode_AddBytes(
    ctx, UsefulBufC{quote.evidence.data(), quote.evidence.size()});
  QCBOREncode_AddBytes(
    ctx, UsefulBufC{quote.endorsements.data(), quote.endorsements.size()});
  QCBOREncode_AddBytes(ctx, UsefulBufC{cose_key.data(), cose_key.size()});
  QCBOREncode_CloseArray(ctx);
}

extern "C" void enclave_main(
        const char* issuer,
        const char* feed,
        const char* url,
        const char* nonce,
        uint8_t* buffer,
        size_t total_length,
        size_t* bytes_written)
{
  oe_load_module_host_socket_interface();
  oe_load_module_host_resolver();
  afetch::Curl::global_init();

  try
  {
    afetch::Curl curl;

    // Fetch URL
    auto response = curl.fetch(url);

    // Create output JSON
    nlohmann::json j;
    j["url"] = url;
    j["nonce"] = nonce;
    j["body"] = afetch::base64(response.body);
    j["certs"] = response.cert_chain;

    std::string data_json = j.dump(1);

    int alg = T_COSE_ALGORITHM_ES256;
    auto key = afetch::create_eckey(alg);

    std::vector<uint8_t> cose_key = afetch::encode_key(alg, key.get());
    Quote quote = get_quote(cose_key);

    t_cose_key key_pair;
    key_pair.k.key_ptr = key.get();
    key_pair.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;

    t_cose_sign1_sign_ctx ctx;
    t_cose_sign1_sign_init(&ctx, 0, alg);
    t_cose_sign1_set_signing_key(&ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    struct q_useful_buf_c result;
    auto err = afetch::cose_sign_with_headers(
      &ctx,
      UsefulBuf{buffer, total_length},
      &result,
      [&](QCBOREncodeContext* cbor_ctx) {
        QCBOREncode_AddSZStringToMapN(
          cbor_ctx, COSE_HEADER_PARAM_CONTENT_TYPE, "application/json");
        QCBOREncode_AddSZStringToMapN(
          cbor_ctx, COSE_HEADER_PARAM_ISSUER, issuer);
        QCBOREncode_AddSZStringToMapN(
          cbor_ctx, COSE_HEADER_PARAM_FEED, feed);
        QCBOREncode_BstrWrapInMap(
          cbor_ctx, COSE_HEADER_PARAM_ATTESTATION_REPORT);
        encode_attestation_report(cbor_ctx, quote, cose_key);
        QCBOREncode_CloseBstrWrap2(cbor_ctx, false, NULL);
      },
      [&](QCBOREncodeContext* cbor_ctx) {},
      [&](QCBOREncodeContext* cbor_ctx) {
        QCBOREncode_AddEncoded(
          cbor_ctx, UsefulBufC{data_json.data(), data_json.size()});
      });

    if (err != T_COSE_SUCCESS)
    {
      throw std::logic_error("Failed to sign message");
    }

    *bytes_written = result.len;
  }
  catch (std::exception& e)
  {
    std::cerr << e.what() << std::endl;
    abort();
  }

  afetch::Curl::global_cleanup();
}
