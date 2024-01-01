# OpenID Connect Prototype

[![MIT licensed][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/david-wallace-croft/openidconnect-prototype/blob/main/LICENSE.txt

- Prototype of using the crate openidconnect

## Setup

- Make a .cargo/config.toml file in the project root for environment variables
  - .cargo is in the .gitignore so the values will not be committed to Git
  - Use placeholder values initially
```
REDIRECT_URL = "http://localhost:8080/"

CLIENT_ID = "a1b2c3"
ISSUER_URL = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_a1b2c3d4e"

PKCE_VERIFIER = "Ab-C1dE_2"

AUTHORIZATION_CODE = "12345678-1234-1234-1234-123456789012"
```
- Set up an Identity Provider (IDP)
  - You can use project cargo-lambda-prototype to set up an AWS Cognito IDP
- Using values from the IDP, update CLIENT_ID and ISSUER_URL in config.toml

## Running Phase 1

- Run phase 1
```
cargo run --bin main1
```
- Using the output, update the PKCE_VERIFIER in config.toml
- Click on the link in the output
- Make a user account if you need to
- Update AUTHORIZATION_CODE in config.toml using the redirect "code" parameter

## Running Phase 2

- Run phase 2
```
cargo run --bin main2
```
- TODO

## Links

- https://github.com/ramosbugs/openidconnect-rs
- https://docs.rs/openidconnect/latest/openidconnect/

## History

- Initial release: 2023-12-19
