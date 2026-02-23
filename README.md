# avs-service
AVS services (SFT etc)

In order to build all that is necessary is to follow the Dockerfile.
If building on anything else than docker, please include all the necessary
pre-requisits as defined in the Dockerfile.

To build:
- Clone this repository using git clone --recursive
- Run docker build ./

## tools/sft_disco
This is the SFT discovery service. It is used to discover the SFT service on the network and to register the SFT service with the AVS service registry.

To build, run the following command in the tools/sft_disco directory:
```
docker build -t sft_disco .
```
