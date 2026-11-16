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
round trip (HelloRetryRequest). The DTLS 1.2 cipher suites and the SRTP
profiles of sftd do not change: Wire clients get TLS_AES_128_GCM_SHA256
with DTLS 1.3 and ECDHE-ECDSA-AES128-GCM-SHA256 with DTLS 1.2, and the
SRTP profile is SRTP_AEAD_AES_256_GCM when the client offers it (AVS
10.5.35 and later), otherwise SRTP_AES128_CM_SHA1_80. Two options change
this:

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

A client that `-D` or `-g` rejects cannot set up media. Its call times out
after about 10 seconds with the end reason "timeout". In a 1:1 call the
other client may end the call too (seen with AVS on macOS); in a group call
the other participants continue. Clients are not told why. Released Wire
clients (checked with AVS 10.5.35) do not offer X25519MLKEM768, so
`-g X25519MLKEM768` rejects them.

When sftd ends a handshake because the peer has no DTLS version or no key
exchange group in common with it, it logs
`reflow: DTLS handshake rejected: no key exchange group in common with the
peer (see -g)` or `... no DTLS version in common with the peer (see -D and
-g)`, and counts the handshake in the metric
`sft_dtls_rejected_total{reason="group"}` or `{reason="version"}`. A client
that retries is counted again. With DTLS 1.2, BoringSSL reports a missing
group as "no shared cipher"; sftd counts it as a group rejection when the
client offers none of the DTLS 1.2 groups of `-g`. Not counted: handshakes
that the peer ends, and handshakes that fail for other reasons, such as no
common cipher suite or a DTLS 1.2 client without P-256, the curve of the sftd
certificate.

## tools/sft_disco
This is the SFT discovery service. It is used to discover the SFT service on the network and to register the SFT service with the AVS service registry.

To build, run the following command in the tools/sft_disco directory:
```
docker build -t sft_disco .
```
