# o2token

A simple tool for debugging and testing Oauth2/OIDC setups

## Is it safe and of high quality?

Not really. But it's simple and usually works.

## How are the received tokens verified?

Not at all. They are accepted "as is" from the IDP endpoint (it's HTTPS... why should you not trust them?)

## OK, so how do I use it?

```shell
go run main.go --help
```

Note that all CLI parameter can be replaced by environment variables starting with `O2TOKEN_`.

***Example:*** `--callback_path` can be replaced by defining `O2TOKEN_CALLBACK_PATH`. 

CLI parameters will always have precedence over environment variables.