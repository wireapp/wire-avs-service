# avs-service
AVS services (SFT etc)

In order to build all that is necessary is to follow the Dockerfile.
If building on anything else than docker, please include all the necessary
pre-requisits as defined in the Dockerfile.

To build:
- Clone this repository using `git clone --recursive`

```bash
git submodule update --init --recursive
# We shuld update avs
cd contrib/avs/ && git checkout main && git pull
```

- Build and run with docker

```bash
# on apple silicon
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

```bash
# build and run
docker-compose up -d 
```


```
./sftd -p '1030' -A '172.16.0.0/12' -M '127.0.0.1' -r '1040' -T -u 'https://127.0.0.1:4200'
```

Parameter:
```
-a              Force authorization
-I <addr>       Address for HTTP requests (default: 127.0.0.1)
-p <port>       Port for HTTP requests (default: 8585)
-A <addr>       Address for media (default: same as request address)
-M <addr>       Address for metrics requests (default: 127.0.0.1)
-r <port>       Port for metrics requests (default: 49090)
-u <URL>        URL to use in responses
-b <blacklist>  Comma seperated client version blacklist Example: <6.2.9,6.2.11
-l <prefix>     Log to file with prefix
-q              Quiet (less-verbose logging)
-T              Use TURN servers when gathering
-t <url>        Multi SFT TURN URL
-s <path>       Multi SFT TURN path to file with secret
-w <count>      Worker count (default: 16)
```