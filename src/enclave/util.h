// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <exception>
#include <iostream>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <qcbor/UsefulBuf.h>
#include <span>
#include <string>
#include <vector>

static constexpr int64_t COSE_HEADER_PARAM_ALG = 1;
static constexpr int64_t COSE_HEADER_PARAM_CONTENT_TYPE = 3;
static constexpr const char* COSE_HEADER_PARAM_ATTESTATION_REPORT =
  "attestation_report";
static constexpr int64_t COSE_HEADER_PARAM_ISSUER = 391;
static constexpr int64_t COSE_HEADER_PARAM_FEED = 392;

static constexpr int64_t COSE_KEY_PARAM_KTY = 1;
static constexpr int64_t COSE_KEY_PARAM_ALG = 3;
static constexpr int64_t COSE_KEY_PARAM_EC2_CRV = -1;
static constexpr int64_t COSE_KEY_PARAM_EC2_X = -2;
static constexpr int64_t COSE_KEY_PARAM_EC2_Y = -3;

static constexpr int64_t COSE_KEY_TYPE_EC2 = 2;

static constexpr int64_t COSE_KEY_CURVE_EC2_P256 = 1;
static constexpr int64_t COSE_KEY_CURVE_EC2_P384 = 2;
static constexpr int64_t COSE_KEY_CURVE_EC2_P521 = 3;

namespace afetch
{
  std::string base64(std::span<const uint8_t> input)
  {
    size_t len_written = 0;

    // Obtain required size for output buffer
    auto rc = mbedtls_base64_encode(
      nullptr, 0, &len_written, input.data(), input.size());
    if (rc < 0 && rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
      throw std::logic_error(
        "Could not obtain length required for encoded base64 buffer");
    }

    std::string b64_string(len_written, '\0');
    auto dest = (uint8_t*)(b64_string.data());

    rc = mbedtls_base64_encode(
      dest, b64_string.size(), &len_written, input.data(), input.size());
    if (rc != 0)
    {
      throw std::logic_error("Could not encode base64 string");
    }

    if (b64_string.size() > 0)
    {
      // mbedtls includes the terminating null, but std-string provides this
      // already
      b64_string.pop_back();
    }

    return b64_string;
  }

  std::array<uint8_t, 32> sha256(std::span<const uint8_t> input)
  {
    std::array<uint8_t, 32> hash;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, input.data(), input.size());
    mbedtls_sha256_finish_ret(&ctx, hash.data());
    mbedtls_sha256_free(&ctx);
    return hash;
  }

  /**
   * Encode a BIGNUM as a CBOR bstr, within a map with the given label.
   *
   * This method is analogous to the QCBOREncode_AddXXXToMapN methods.
   */
  void encode_bignum_to_map(
    QCBOREncodeContext* ctx, int64_t label, const BIGNUM* bn)
  {
    UsefulBuf buffer;
    QCBOREncode_OpenBytesInMapN(ctx, label, &buffer);
    if (buffer.ptr)
    {
      BN_bn2bin(bn, (uint8_t*)buffer.ptr);
    }
    QCBOREncode_CloseBytes(ctx, BN_num_bytes(bn));
  }

  /**
   * Encode an OpenSSL PKEY as a COSE Key.
   *
   * Only EC keys are supported.
   */
  std::vector<uint8_t> encode_key(int alg, EVP_PKEY* pkey)
  {
    EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec_key)
    {
      throw std::logic_error("Unsupported public key type.");
    }

    const EC_POINT* ec_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x(BN_new(), &BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y(BN_new(), &BN_free);

    EC_POINT_get_affine_coordinates(ec_group, ec_point, x.get(), y.get(), NULL);

    QCBOREncodeContext ctx;
    std::vector<uint8_t> buffer(10 * 1024);
    QCBOREncode_Init(&ctx, UsefulBuf{buffer.data(), buffer.size()});

    QCBOREncode_OpenMap(&ctx);
    QCBOREncode_AddInt64ToMapN(&ctx, COSE_KEY_PARAM_KTY, COSE_KEY_TYPE_EC2);
    QCBOREncode_AddInt64ToMapN(&ctx, COSE_KEY_PARAM_ALG, alg);

    // OpenSSL does not have a trivial way to recover the curve name from the
    // PKEY object. Instead we assume the curve matches the chosen algorithm.
    switch (alg)
    {
      case T_COSE_ALGORITHM_ES256:
        QCBOREncode_AddInt64ToMapN(
          &ctx, COSE_KEY_PARAM_EC2_CRV, COSE_KEY_CURVE_EC2_P256);
        break;
      case T_COSE_ALGORITHM_ES384:
        QCBOREncode_AddInt64ToMapN(
          &ctx, COSE_KEY_PARAM_EC2_CRV, COSE_KEY_CURVE_EC2_P384);
        break;
      case T_COSE_ALGORITHM_ES512:
        QCBOREncode_AddInt64ToMapN(
          &ctx, COSE_KEY_PARAM_EC2_CRV, COSE_KEY_CURVE_EC2_P521);
        break;
      default:
        throw std::logic_error("Invalid COSE algorithm");
    }

    encode_bignum_to_map(&ctx, COSE_KEY_PARAM_EC2_X, x.get());
    encode_bignum_to_map(&ctx, COSE_KEY_PARAM_EC2_Y, y.get());
    QCBOREncode_CloseMap(&ctx);

    UsefulBufC result;
    QCBORError err = QCBOREncode_Finish(&ctx, &result);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to encode COSE Key");
    }
    buffer.resize(result.len);

    return buffer;
  }

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> create_eckey(int32_t alg)
  {
    int ossl_curve_nid;
    switch (alg)
    {
      case T_COSE_ALGORITHM_ES256:
        ossl_curve_nid = NID_X9_62_prime256v1;
        break;

      case T_COSE_ALGORITHM_ES384:
        ossl_curve_nid = NID_secp384r1;
        break;

      case T_COSE_ALGORITHM_ES512:
        ossl_curve_nid = NID_secp521r1;
        break;

      default:
        throw std::logic_error("Invalid COSE algorithm ");
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), &EVP_PKEY_CTX_free);
    if (!ctx)
    {
      throw std::logic_error("PKEY_CTX_new_id failed");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1)
    {
      throw std::logic_error("PKEY_keygen_init failed");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), ossl_curve_nid) != 1)
    {
      throw std::logic_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
    }

    EVP_PKEY* pkey = NULL;
    int result = EVP_PKEY_keygen(ctx.get(), &pkey);
    if (result != 1)
    {
      throw std::logic_error("EVP_PKEY_keygen failed");
    }

    return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(
      pkey, &EVP_PKEY_free);
  }

  /**
   * Create a COSE Sign1 message, with custom header parameters.
   *
   * This function should be called with three callables, which will be invoked
   * successively to encode the protected header parameters, the unprotected one
   * and the message payload.
   */
  template <typename F1, typename F2, typename F3>
  requires std::is_invocable_v<F1, QCBOREncodeContext*> &&
    std::is_invocable_v<F2, QCBOREncodeContext*> &&
    std::is_invocable_v<F3, QCBOREncodeContext*>
      t_cose_err_t cose_sign_with_headers(
        t_cose_sign1_sign_ctx* ctx,
        struct q_useful_buf out_buf,
        struct q_useful_buf_c* result,
        F1 add_protected_headers,
        F2 add_unprotected_headers,
        F3 add_payload)
  {
    QCBOREncodeContext cbor_ctx;
    QCBOREncode_Init(&cbor_ctx, out_buf);

    QCBOREncode_AddTag(&cbor_ctx, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(&cbor_ctx);

    // protected
    QCBOREncode_BstrWrap(&cbor_ctx);
    QCBOREncode_OpenMap(&cbor_ctx);
    QCBOREncode_AddInt64ToMapN(
      &cbor_ctx, COSE_HEADER_PARAM_ALG, ctx->cose_algorithm_id);
    add_protected_headers(&cbor_ctx);
    QCBOREncode_CloseMap(&cbor_ctx);

    // Close the protected headers, and save its position into ctx.
    // This abuses t_cose implementation details a bit.
    QCBOREncode_CloseBstrWrap2(&cbor_ctx, false, &ctx->protected_parameters);

    // unprotected
    QCBOREncode_OpenMap(&cbor_ctx);
    add_unprotected_headers(&cbor_ctx);
    QCBOREncode_CloseMap(&cbor_ctx);

    // body
    QCBOREncode_BstrWrap(&cbor_ctx);
    add_payload(&cbor_ctx);

    // signature
    // t_cose_sign1_encode_signature expects the encoder to be mid-BstrWrap.
    // It will close the BstrWrap and use that to determine the boundary of the
    // payload.
    t_cose_err_t err = t_cose_sign1_encode_signature(ctx, &cbor_ctx);
    if (err != T_COSE_SUCCESS)
    {
      return err;
    }

    QCBORError cbor_err = QCBOREncode_Finish(&cbor_ctx, result);
    if (cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL)
    {
      return T_COSE_ERR_TOO_SMALL;
    }
    else if (cbor_err != QCBOR_SUCCESS)
    {
      return T_COSE_ERR_CBOR_FORMATTING;
    }
    else
    {
      return T_COSE_SUCCESS;
    }
  }
}
