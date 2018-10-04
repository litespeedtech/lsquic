# Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE.
SET(TEST_PREFIX "ietf")
ENABLE_TESTING()

INCLUDE_DIRECTORIES( ../../include )
INCLUDE_DIRECTORIES( ../../src/liblsquic )

SET(LIBS lsquic pthread libssl.a libcrypto.a z m ${FIULIB})

FOREACH(TEST_NAME parse varint crypto_gen)
    ADD_EXECUTABLE(test_${TEST_NAME} test_${TEST_NAME}.c)
    TARGET_LINK_LIBRARIES(test_${TEST_NAME} ${LIBS})
    ADD_TEST(${TEST_PREFIX}-${TEST_NAME} test_${TEST_NAME})
ENDFOREACH()
