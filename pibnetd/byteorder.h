/*
 * byteorder.h - Endian convert macros
 *
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef _BYTEORDER_H_
#define _BYTEORDER_H_

#include <stdint.h>
#include <endian.h>

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef uint16_t  __be16;
typedef uint32_t  __be32;
typedef uint64_t  __be64;

#if __BYTE_ORDER   == __LITTLE_ENDIAN
#define cpu_to_be16(x)	({			\
	uint16_t _v = (uint16_t)(x);		\
	(uint16_t)((_v << 8) | ((_v >> 8) & 0xFF));	\
		})
#define be16_to_cpu(x)	cpu_to_be16(x)
#define cpu_to_be32(x)	__builtin_bswap32(x)
#define be32_to_cpu(x)	__builtin_bswap32(x)
#define cpu_to_be64(x)	__builtin_bswap64(x)
#define be64_to_cpu(x)	__builtin_bswap64(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be16(x)	(x)
#define cpu_to_be32(x)	(x)
#define cpu_to_be64(x)	(x)
#define be16_to_cpu(x)	(x)
#define be32_to_cpu(x)	(x)
#define be64_to_cpu(x)	(x)
#endif

#endif /* _BYTEORDER_H_ */

