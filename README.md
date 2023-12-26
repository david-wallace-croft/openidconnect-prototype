# OpenID Connect Prototype

[![MIT licensed][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/david-wallace-croft/dioxus-prototype/blob/main/LICENSE.txt

- Prototype of using the crate openidconnect

## Setup

- Make a .cargo/config.toml file in the project root for environment variables
  - .cargo is in the .gitignore so the values will not be committed to Git
```
CLIENT_ID = "a1b2c3"
ISSUER_URL = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_a1b2c3d4e"
REDIRECT_URL = "http://localhost:8080/"
```

## Links

- https://github.com/ramosbugs/openidconnect-rs
- https://docs.rs/openidconnect/latest/openidconnect/

## History

- Initial release: 2023-12-19
