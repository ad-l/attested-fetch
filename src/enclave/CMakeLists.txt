# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Used by imported targets from openenclave-curl.
# These are dummy targets as Open Enclave provides OpenSSL.
add_library(_dummy INTERFACE)
add_library(OpenSSL::SSL ALIAS _dummy)
add_library(OpenSSL::Crypto ALIAS _dummy)

include(${openenclave_curl_BUILD_DIR}/targets.cmake)

set(QCBOR_DIR "${CMAKE_SOURCE_DIR}/../3rdparty/QCBOR")
set(QCBOR_SRC "${QCBOR_DIR}/src")
set(QCBOR_INC "${QCBOR_DIR}/inc")
set(QCBOR_SRCS
  "${QCBOR_SRC}/ieee754.c"
  "${QCBOR_SRC}/qcbor_decode.c"
  "${QCBOR_SRC}/qcbor_encode.c"
  "${QCBOR_SRC}/qcbor_err_to_str.c"
  "${QCBOR_SRC}/UsefulBuf.c"
)
add_library(qcbor.enclave STATIC ${QCBOR_SRCS})
target_include_directories(qcbor.enclave PUBLIC "${QCBOR_INC}")

set(T_COSE_DIR "${CMAKE_SOURCE_DIR}/../3rdparty/t_cose")
set(T_COSE_SRC "${T_COSE_DIR}/src")
set(T_COSE_INC "${T_COSE_DIR}/inc")
set(T_COSE_DEFS -DT_COSE_USE_OPENSSL_CRYPTO=1 -DT_COSE_DISABLE_SHORT_CIRCUIT_SIGN=1)
set(T_COSE_SRCS
  "${T_COSE_SRC}/t_cose_parameters.c"
  "${T_COSE_SRC}/t_cose_sign1_sign.c"
  "${T_COSE_SRC}/t_cose_util.c"
  "${T_COSE_DIR}/crypto_adapters/t_cose_openssl_crypto.c"
)
add_library(t_cose.enclave STATIC ${T_COSE_SRCS})
target_compile_definitions(t_cose.enclave PRIVATE ${T_COSE_DEFS})
target_compile_options(t_cose.enclave INTERFACE ${T_COSE_OPTS_INTERFACE})
target_include_directories(t_cose.enclave PUBLIC "${T_COSE_INC}" PRIVATE "${T_COSE_SRC}")
target_link_libraries(t_cose.enclave PUBLIC qcbor.enclave)

add_custom_command(OUTPUT afetch_t.h afetch_t.c afetch_args.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../afetch.edl
    COMMAND openenclave::oeedger8r
    --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../afetch.edl)

add_library(afetch.enclave SHARED
    enclave.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/afetch_t.c)

# Needed for the generated file fetch_t.h
target_include_directories(afetch.enclave PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/../3rdparty/nlohmann-json/single_include
    )

target_link_libraries(afetch.enclave
    openenclave-curl::libcurl
    openenclave::oecryptombedtls
    openenclave::oeenclave
    openenclave::oelibc
    qcbor.enclave
    t_cose.enclave)

# Generate an ephemeral signing key
set(signing_key ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem)
add_custom_command(
    OUTPUT ${signing_key}
    COMMAND openssl genrsa -out ${signing_key} -3 3072
)

# Sign the enclave
set(signed_enclave ${CMAKE_CURRENT_BINARY_DIR}/libafetch.enclave.so.signed)
set(oe_conf ${CMAKE_CURRENT_LIST_DIR}/oe_sign.conf)
add_custom_command(
    OUTPUT ${signed_enclave}
    COMMAND
    openenclave::oesign sign -e ${CMAKE_CURRENT_BINARY_DIR}/libafetch.enclave.so -c
    ${oe_conf} -k ${signing_key}
    DEPENDS afetch.enclave ${oe_conf} ${signing_key}
)

add_custom_target(
    afetch.enclave_signed ALL
    DEPENDS ${signed_enclave}
)

install(FILES ${signed_enclave}
    DESTINATION .
)
