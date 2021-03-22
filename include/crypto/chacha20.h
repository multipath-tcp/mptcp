/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for the ChaCha20 algorithm
 */

#ifndef _CRYPTO_CHACHA20_H
#define _CRYPTO_CHACHA20_H

#include <crypto/skcipher.h>
#include <linux/types.h>
#include <linux/crypto.h>

#define CHACHA20_IV_SIZE	16
#define CHACHA20_KEY_SIZE	32
#define CHACHA20_BLOCK_SIZE	64
#define CHACHA20_BLOCK_WORDS	(CHACHA20_BLOCK_SIZE / sizeof(u32))

struct chacha20_ctx {
	u32 key[8];
};

void chacha20_block(u32 *state, u32 *stream);
void crypto_chacha20_init(u32 *state, struct chacha20_ctx *ctx, u8 *iv);
int crypto_chacha20_setkey(struct crypto_skcipher *tfm, const u8 *key,
			   unsigned int keysize);
int crypto_chacha20_crypt(struct skcipher_request *req);

static inline void chacha_init_consts(u32 *state)
{
	state[0]  = 0x61707865; /* "expa" */
	state[1]  = 0x3320646e; /* "nd 3" */
	state[2]  = 0x79622d32; /* "2-by" */
	state[3]  = 0x6b206574; /* "te k" */
}

#endif
