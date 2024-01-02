// use anyhow::anyhow;
use oauth2::basic::*;
use oauth2::revocation::*;
use openidconnect::core::*;
use openidconnect::reqwest::http_client;
use openidconnect::*;
// use url::Url;

type AliasClient = Client<
  EmptyAdditionalClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
  CoreJsonWebKeyUse,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<BasicErrorResponseType>,
  StandardTokenResponse<
    IdTokenFields<
      EmptyAdditionalClaims,
      EmptyExtraTokenFields,
      CoreGenderClaim,
      CoreJweContentEncryptionAlgorithm,
      CoreJwsSigningAlgorithm,
      CoreJsonWebKeyType,
    >,
    BasicTokenType,
  >,
  BasicTokenType,
  StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
  StandardRevocableToken,
  StandardErrorResponse<RevocationErrorResponseType>,
>;

type AliasIdToken = IdToken<
  EmptyAdditionalClaims,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
>;

type AliasIdTokenVerifier<'a> = IdTokenVerifier<
  'a,
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
  CoreJsonWebKeyUse,
  CoreJsonWebKey,
>;

type AliasProviderMetadata = ProviderMetadata<
  EmptyAdditionalProviderMetadata,
  CoreAuthDisplay,
  CoreClientAuthMethod,
  CoreClaimName,
  CoreClaimType,
  CoreGrantType,
  CoreJweContentEncryptionAlgorithm,
  CoreJweKeyManagementAlgorithm,
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
  CoreJsonWebKeyUse,
  CoreJsonWebKey,
  CoreResponseMode,
  CoreResponseType,
  CoreSubjectIdentifierType,
>;

#[derive(Debug)]
pub struct Input {
  authorization_code: String,
  client_id: String,
  issuer_url: String,
  nonce: String,
  pkce_verifier: String,
  redirect_url: String,
}

pub fn load_input_from_env() -> Result<Input, anyhow::Error> {
  let authorization_code: String = std::env::var("AUTHORIZATION_CODE")?;
  let client_id: String = std::env::var("CLIENT_ID")?;
  let issuer_url: String = std::env::var("ISSUER_URL")?;
  let nonce: String = std::env::var("NONCE")?;
  let pkce_verifier: String = std::env::var("PKCE_VERIFIER")?;
  let redirect_url: String = std::env::var("REDIRECT_URL")?;
  let input = Input {
    authorization_code,
    client_id,
    issuer_url,
    nonce,
    pkce_verifier,
    redirect_url,
  };
  Ok(input)
}

pub fn load_input_then_run1() -> Result<(), anyhow::Error> {
  let input = load_input_from_env()?;
  dbg!(&input);
  run1_with_input(&input)
}

pub fn load_input_then_run2() -> Result<(), anyhow::Error> {
  let input = load_input_from_env()?;
  dbg!(&input);
  run2_with_input(&input)
}

fn make_client(
  input: &Input,
  provider_metadata: AliasProviderMetadata,
) -> Result<AliasClient, anyhow::Error> {
  let client_id = ClientId::new(input.client_id.clone());
  // Create an OpenID Connect client by specifying the client ID,
  // client secret, authorization URL and token URL.
  let client: AliasClient = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        // Some(ClientSecret::new("client_secret".to_string())),
        None,
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(input.redirect_url.clone())?);
  dbg!(&client);
  Ok(client)
}

fn make_provider_metadata(
  input: &Input
) -> Result<AliasProviderMetadata, anyhow::Error> {
  let provider_metadata: AliasProviderMetadata =
    CoreProviderMetadata::discover(
      &IssuerUrl::new(input.issuer_url.clone())?,
      http_client,
    )?;
  dbg!(&provider_metadata);
  Ok(provider_metadata)
}

pub fn run1() {
  let result = load_input_then_run1();
  match result {
    Ok(_) => eprintln!("Success"),
    Err(e) => eprintln!("{e}"),
  }
}

pub fn run2() {
  let result = load_input_then_run2();
  match result {
    Ok(_) => eprintln!("Success"),
    Err(e) => eprintln!("{e}"),
  }
}

pub fn run1_with_input(input: &Input) -> Result<(), anyhow::Error> {
  println!("Running prototype");
  // https://cognito-idp.us-east-1.amazonaws.com/us-east-1_a1b2c3/.well-known/openid-configuration

  let provider_metadata: AliasProviderMetadata = make_provider_metadata(input)?;
  let client: AliasClient = make_client(input, provider_metadata)?;
  let (pkce_challenge, pkce_verifier): (PkceCodeChallenge, PkceCodeVerifier) =
    PkceCodeChallenge::new_random_sha256();
  let (authorization_url, _csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        // .add_scope(Scope::new("openid".to_string()))
        // .add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();
  println!("Nonce: {}", nonce.secret());
  println!("PKCE Verifier: {}", pkce_verifier.secret());
  println!("Authorization URL: {}", authorization_url);
  Ok(())
}

pub fn run2_with_input(input: &Input) -> Result<(), anyhow::Error> {
  let provider_metadata: AliasProviderMetadata = make_provider_metadata(input)?;
  let client: AliasClient = make_client(input, provider_metadata)?;

  // Once the user has been redirected to the redirect URL, you'll have access to the
  // authorization code. For security reasons, your code should verify that the `state`
  // parameter returned by the server matches `csrf_state`.

  // Now you can exchange it for an access token and ID token.
  let token_response = client
        .exchange_code(AuthorizationCode::new(input.authorization_code.clone()
        ))
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(input.pkce_verifier.clone()))
        .request(http_client)?;

  dbg!(&token_response);

  // Extract the ID token claims after verifying its authenticity and nonce.
  let id_token: &AliasIdToken = token_response
    .id_token()
    .ok_or_else(|| anyhow::anyhow!("Server did not return an ID token"))?;

  dbg!(id_token);

  let id_token_verifier: AliasIdTokenVerifier = client.id_token_verifier();

  let nonce = Nonce::new(input.nonce.clone());

  let claims = id_token.claims(&id_token_verifier, &nonce)?;

  dbg!(claims);

  // Verify the access token hash to ensure that the access token hasn't been substituted for
  // another user's.

  let access_token_hash_option: Option<&AccessTokenHash> =
    claims.access_token_hash();

  if let Some(expected_access_token_hash) = access_token_hash_option {
    let actual_access_token_hash = AccessTokenHash::from_token(
      token_response.access_token(),
      &id_token.signing_alg()?,
    )?;
    if actual_access_token_hash != *expected_access_token_hash {
      return Err(anyhow::anyhow!("Invalid access token"));
    }
  }

  // The authenticated user's identity is now available. See the IdTokenClaims
  // struct for a complete listing of the available claims.

  let subject: &str = claims.subject().as_str();

  let email: &str = claims
    .email()
    .map(|email| email.as_str())
    .unwrap_or("<not provided>");

  println!(
    "User {} with e-mail address {} has authenticated successfully",
    subject, email
  );

  // If available, we can use the UserInfo endpoint to request additional information.

  // The user_info request uses the AccessToken returned in the token response. To parse custom
  // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
  // CoreUserInfoClaims type alias.

  let access_token: AccessToken = token_response.access_token().to_owned();

  let user_info_request = client
    .user_info(access_token, None)
    .map_err(|err| anyhow::anyhow!("No user info endpoint: {:?}", err))?;

  // TODO: The following code is failing with this error message:
  // Failed requesting user info: Parse(Error { path: Path { segments: [] },
  // original: Error("invalid type: string \"true\", expected a boolean",
  // line: 1, column: 129) })

  // let userinfo: CoreUserInfoClaims = user_info_request
  //   .request(http_client)
  //   .map_err(|err| anyhow::anyhow!("Failed requesting user info: {:?}", err))?;

  // dbg!(userinfo);

  // See the OAuth2TokenResponse trait for a listing of other available fields such as
  // access_token() and refresh_token().

  Ok(())
}
