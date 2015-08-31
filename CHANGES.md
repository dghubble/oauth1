# OAuth1 Changelog

## v.1.0.0-rc1 (2015-08-30)

* Improved OAuth 1 spec compliance and test coverage.
* Added `func StaticTokenSource(*Token) TokenSource`
* Added `ParseAuthorizationCallback` function. Removed `Config.HandleAuthorizationCallback` method.
* Changed `Config` method signatures to allow an interface to be defined for the OAuth1 authorization flow. Gives users of this package (and downstream packages) the freedom to use other implementations if they wish.
* Removed `RequestToken` in favor of passing token and secret value strings.
* Removed `ReuseTokenSource` struct, it was effectively a static source. Replaced by `StaticTokenSource`. (breaking)

## v0.1.0 (2015-04-26)

* Initial OAuth1 support for obtaining authorization and making authorized requests