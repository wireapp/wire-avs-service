# avs-service
AVS services (SFT etc)

In order to build all that is necessary is to follow the Dockerfile.
If building on anything else than docker, please include all the necessary
pre-requisits as defined in the Dockerfile.

To build:
- Clone this repository using git clone --recursive
- Run docker build ./

To run the tests (DTLS handshakes, the reflow module, sftd startup):
`make test`

## DTLS

sftd accepts DTLS 1.2 and 1.3. It offers the key exchange groups
X25519MLKEM768 (hybrid post-quantum, DTLS 1.3 only), X25519, P-256 and
MLKEM1024 (post-quantum, DTLS 1.3 only), and
picks the first one in this order that the client supports, whatever the
client's own order. A client that supports X25519MLKEM768 gets it; if its
first message carries no X25519MLKEM768 key share, this costs one extra
round trip (HelloRetryRequest). The cipher suites do not change: Wire
clients get TLS_AES_128_GCM_SHA256 with DTLS 1.3 and
ECDHE-ECDSA-AES128-GCM-SHA256 with DTLS 1.2, and the SRTP profile is
SRTP_AEAD_AES_256_GCM when the client offers it. Two options change this:

- `-D` rejects clients that only support DTLS 1.2.
- `-g <groups>` sets the groups as a comma separated list, most preferred
  first, for example `-g X25519MLKEM768`. A client that supports none of
  them cannot connect. The names are those of BoringSSL: X25519MLKEM768,
  X25519, P-256, P-384, P-521 and others. sftd exits at startup if a name
  is unknown. If no group in the list works with DTLS 1.2 (as with
  `-g X25519MLKEM768`), sftd accepts DTLS 1.3 only and logs a warning.

Both options also apply when sftd connects to another SFT (federation and
multi-SFT calls). An SFT from a release without these options supports
DTLS 1.2 only, so with `-D`, or with a `-g` list that DTLS 1.2 cannot use,
calls that involve such an SFT fail.

On each established connection sftd logs the negotiated version and group,
for example `DTLS version=0xfefc group=0x11ec (X25519MLKEM768)`.

## tools/sft_disco
This is the SFT discovery service. It is used to discover the SFT service on the network and to register the SFT service with the AVS service registry.

To build, run the following command in the tools/sft_disco directory:
```
docker build -t sft_disco .
```
