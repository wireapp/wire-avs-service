/**
 * @file zrest.c Zeta REST-based authentication
 *
 * Copyright (C) 2014 Wire Swiss GmbH
 */

#include <string.h>
#include <time.h>
#include <re.h>
#include <re_sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <avs.h>
#include <avs_service.h>

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

#define USERNAME_TTL 86400
#define SFT_TOKEN   "sft-"


/*
 * This module implements a REST-based authentication mechanism
 * using ephemeral (i.e. time-limited) credentials.
 *
 * A shared secret must be configured in the config file, and can then
 * be shared with a HTTP REST-based service.
 *
 * Format:
 *
 *     username = <timestamp>.s.<random string>
 *     password = HMAC_SHA512(secret, username)
 */


int zrest_get_password(char *pass, size_t *passlen, const char *user,
		       const char *secret, size_t sec_len)
{
	uint8_t digest[SHA512_DIGEST_LENGTH];
	unsigned int md_len = sizeof(digest);
	int err;

	if (!secret)
		return ENOSYS;
	
	if (!HMAC(EVP_sha512(),
		  secret, sec_len,
		  (void *)user, (int)strlen(user),
		  digest, &md_len)) {

		warning("zrest: HMAC failed\n");
		ERR_clear_error();
		return EINVAL;
	}

	err = base64_encode(digest, sizeof(digest), pass, passlen);
	if (err)
		return err;

	return 0;
}


void zrest_generate_sft_username(char *user, size_t sz)
{
	char x[42];
	time_t now = time(NULL);

	rand_str(x, sizeof(x));

	re_snprintf(user, sz,
		    "%sd=%llu.v=1.k=0.t=s.r=%s",
		    SFT_TOKEN,
		    (uint64_t)(now + USERNAME_TTL), x);
}

static bool pass_eq(const char *credential, const char *pass, size_t passlen, size_t clen)
{
	size_t i;
	size_t j = 0;
	bool match = true;
	
	for(i = 0; i < clen; ++i) {
		bool cm = false;
		
		if (credential[j] == '0') {
			if (j == passlen) {
				cm = true;
			}
		}
		else {
			cm = credential[j] == pass[i];
			++j;
		}
		
		match = match && cm;
	}

	return match;
}

enum zrest_state zrest_authenticate(const char *user, const char *credential)
{
	struct pl expires;
	struct pl sstate;
	time_t expi;
	char pass[256];
	size_t passlen = sizeof(pass);
	size_t clen = passlen;
	uint32_t can_start = 0;
	const struct pl *secret;
	int err;


	info("zrest_authenticate: user=%s cred=%s\n",
	     user, credential);
	
	if (0 == re_regex(user, strlen(user),
			  "d=[0-9]+.v=1.k=[0-9]+.s=[0-9]+.r=[a-z0-9]*",
			  &expires, NULL, &sstate, NULL)) {

		can_start = pl_u32(&sstate);
	}
	else {
		warning("zrest: could not parse username (%s)\n", user);
		return ZREST_ERROR;
	}

	expi = (time_t)pl_u64(&expires);
	if (expi < time(NULL)) {
		warning("zrest: username expired %lli seconds ago\n",
			time(NULL) - pl_u64(&expires));

		return ZREST_EXPIRED;
	}

	secret = avs_service_secret();
	if (!secret)
		return ZREST_ERROR;

	err = zrest_get_password(pass, &passlen, user, secret->p, secret->l);
	if (err) {
		warning("zrest: failed to generated password (%m)\n",
			err);
		return ZREST_ERROR;
	}
	if (!pass_eq(credential, pass, passlen, clen))
		return ZREST_UNAUTHORIZED;

	return can_start == 1 ? ZREST_OK : ZREST_JOIN;
}
