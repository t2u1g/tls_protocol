#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>

#include "tls_record.h"
#include "tls_common.h"
#include "./win32/win32_sockets.h"

// this file contains heght level protocol-handshaking related.

/*
 * at first TLS_RECORD_CONTEXT must have vaild socke
 * hashalgorithm is hash_null
 * ciper_type is Ciper_stream
 * bulk_ciper_algorithm is bulk_null
 * */
#define TLS_RECORD_CONTEXT_BUFFER_SIZE  ((1 << 14) + 2048)
