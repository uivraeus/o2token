# o2token

A simple tool for debugging and testing Oauth2/OIDC setups

## Is it safe and of high quality?

Not really. But it's simple and usually works.

## How are the received tokens verified?

Not at all. Any token is accepted "as is" from the IDP endpoint (it's HTTPS... why should you not trust them?)

## OK, so how do I use it?

```shell
make run --help
```

Or build the binary first

```shell
make
bin/o2token --help
```

Note that all CLI parameter can be replaced by environment variables starting with `O2TOKEN_`.

***Example:*** `--callback-path` can be replaced by defining `O2TOKEN_CALLBACK_PATH`. 

CLI parameters will always have precedence over environment variables.

## Examples

### Eternal refresh loop

By including the `offline_access` and extracting the `refresh_token` from the response it is possible to obtain new tokens, again and again, by running this command (assuming that IDP and client id/secret details are defined via `O2TOKEN_` environment variables).

```shell
export O2TOKEN_REFRESH_TOKEN=$(bin/o2token --verbose=false | tee /dev/tty | jq -r '.refresh_token')
```

If the `O2TOKEN_REFRESH_TOKEN` variable is empty (e.g. the first time), a normal OAuth2 code flow is initiated. After that the refresh flow will be triggered each time the command is run.

