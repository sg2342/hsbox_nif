/*
 * Copyright (c) 2014 Vincent Hanquez <vincent@snarc.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef CRYPTON_SALSA
#define CRYPTON_SALSA

typedef union {
	uint64_t q[8];
	uint32_t d[16];
	uint8_t  b[64];
} block;

typedef block crypton_salsa_state;

typedef struct {
	crypton_salsa_state st;
	uint8_t prev[64];
	uint8_t prev_ofs;
	uint8_t prev_len;
	uint8_t nb_rounds;
} crypton_salsa_context;

/* for scrypt */
void crypton_salsa_core_xor(int rounds, block *out, block *in);

void crypton_salsa_init_core(crypton_salsa_state *st, uint32_t keylen, const uint8_t *key, uint32_t ivlen, const uint8_t *iv);
void crypton_salsa_init(crypton_salsa_context *ctx, uint8_t nb_rounds, uint32_t keylen, const uint8_t *key, uint32_t ivlen, const uint8_t *iv);
void crypton_salsa_combine(uint8_t *dst, crypton_salsa_context *st, const uint8_t *src, uint32_t bytes);
void crypton_salsa_generate(uint8_t *dst, crypton_salsa_context *st, uint32_t bytes);

#endif
