# OAuth1 Changelog

## latest (TBD)

* Improvements to OAuth 1 spec compliance and test coverage.
* Added `func StaticTokenSource(*Token) TokenSource`
* Removed ReuseTokenSource struct, it was effectively a static source. Replaced by StaticTokenSource. (breaking)

## v0.1.0 (2015-04-26)

* Initial OAuth1 support for obtaining authorization and making authorized requests