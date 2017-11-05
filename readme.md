# ABNF Validator

[![Build Status](https://travis-ci.org/squid-lang/abnf-validator.svg?branch=master)](https://travis-ci.org/squid-lang/abnf-validator)

This is based of [Chris Newman's ABNF Validator](http://www.apps.ietf.org/content/chris-newmans-abnf-validator) which is public domain.
I have added some small changes to better suit my needs.

## Modifications

- All cgi-related code has been removed ([88aecb1](https://github.com/squid-lang/abnf-validator/commit/03be0d7de1a605bb319d20fcca1e5782f23c62bd))
- The first rule is always marked as referenced ([9c68e5d](https://github.com/squid-lang/abnf-validator/commit/9c68e5d041140c50056f337dcdfba8357fb7e302))
