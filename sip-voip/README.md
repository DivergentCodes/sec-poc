# sipcall

A Docker image that builds and runs `baresip` to make outbound SIP calls.

## Build

```sh
docker build -t sipcall .
```

## Configure

```sh
# .env
SIP_SERVER="my.sip.provider.com"
SIP_USERNAME="bob"
SIP_PASSWORD="hunter2"
SIP_PHONE_NUMBER="18005554444"
TARGET_PHONE_NUMBER="15035556666"
```

# Run

```sh
docker run --rm --env-file .env sipcall
```
