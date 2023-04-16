# ABNF Validator
This is a fork of [Chris Newman's ABNF Validator](https://web.archive.org/web/20181228051239/https://www.apps.ietf.org/content/chris-newmans-abnf-validator), which is public domain, with some opinionated modifications.

The modified code is public domain.

## Modifications
* All cgi-related code has been removed ([88aecb1](https://github.com/squid-lang/abnf-validator/commit/03be0d7de1a605bb319d20fcca1e5782f23c62bd))
* The first rule is always marked as referenced ([9c68e5d](https://github.com/squid-lang/abnf-validator/commit/9c68e5d041140c50056f337dcdfba8357fb7e302))
* Errors and Warnings always produce a non-zero [exit status](https://en.wikipedia.org/wiki/Exit_status) ([939e7aa](https://github.com/squid-lang/abnf-validator/commit/939e7aac9d9b99cbe64224723b4240aff3abcc7a))

## Usage
The program accepts abnf input through STDIN.

Example:

```sh
cat syntax.abnf | ./abnf
```

## Building
Building requires `gcc` and `make`.

```sh
make
```
