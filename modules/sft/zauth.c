#include <string.h>
#include <time.h>
#include <re.h>
#include <re_sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <avs.h>

#include "zauth.h"

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

#define USERNAME_TTL 86400
#define SFT_TOKEN   "sft-"

void zauth_get_username(char *user, size_t sz)
{
	char x[42];
	time_t now = time(NULL);

	rand_str(x, sizeof(x));

	re_snprintf(user, sz,
		    "%sd=%llu.v=1.k=0.t=s.r=%s",
		    SFT_TOKEN,
		    (uint64_t)(now + USERNAME_TTL), x);
}

int zauth_get_password(char *pass, size_t *passlen, const char *user,
		       const char *secret, size_t secret_len)
{
	uint8_t digest[SHA512_DIGEST_LENGTH];
	unsigned int md_len = sizeof(digest);
	int err;

	if (!HMAC(EVP_sha512(),
		  secret, (int)secret_len,
		  (void *)user, (int)strlen(user),
		  digest, &md_len)) {

		warning("zauth: HMAC failed\n");
		ERR_clear_error();
		return EINVAL;
	}

	err = base64_encode(digest, sizeof(digest), pass, passlen);

	info("generate_pass: secret=%s(%d) user=%s pass=%b\n",
	     secret, (int)secret_len, user, pass, passlen);
	
	if (err)
		return err;

	return 0;
}
