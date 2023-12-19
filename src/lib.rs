use anyhow::anyhow;
use openidconnect::core::{
  CoreAuthDisplay, CoreAuthenticationFlow, CoreClaimName, CoreClaimType,
  CoreClient, CoreClientAuthMethod, CoreGrantType, CoreJsonWebKey,
  CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
  CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
  CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
  CoreUserInfoClaims,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
  AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId,
  ClientSecret, CsrfToken, EmptyAdditionalProviderMetadata, IssuerUrl, Nonce,
  PkceCodeChallenge, ProviderMetadata, RedirectUrl, Scope,
};
use url::Url;

// Use OpenID Connect Discovery to fetch the provider metadata.
use openidconnect::{OAuth2TokenResponse, TokenResponse};

pub fn run_prototype() -> Result<(), anyhow::Error> {
  println!("Running prototype");
  // https://cognito-idp.us-east-1.amazonaws.com/us-east-1_25FApjxwv/.well-known/openid-configuration
  let provider_metadata: ProviderMetadata<
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
  > = CoreProviderMetadata::discover(
    &IssuerUrl::new(
      "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_25FApjxwv"
        .to_string(),
    )?,
    http_client,
  )?;

  println!("{:?}", provider_metadata);

  // Create an OpenID Connect client by specifying the client ID,
  // client secret, authorization URL and token URL.
  let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new("60r0untiiapb0ah88270hovl3d".to_string()),
        // Some(ClientSecret::new("client_secret".to_string())),
        None,
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080".to_string())?);

  // Generate a PKCE challenge.
  let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

  // Generate the full authorization URL.
  let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

  // This is the URL you should redirect the user to, in order to trigger the authorization
  // process.
  println!("Browse to: {}", auth_url);

  // Once the user has been redirected to the redirect URL, you'll have access to the
  // authorization code. For security reasons, your code should verify that the `state`
  // parameter returned by the server matches `csrf_state`.

  // // Now you can exchange it for an access token and ID token.
  // let token_response = client
  //       .exchange_code(AuthorizationCode::new(
  //           "some authorization code".to_string(),
  //       ))
  //       // Set the PKCE code verifier.
  //       .set_pkce_verifier(pkce_verifier)
  //       .request(http_client)?;

  // // Extract the ID token claims after verifying its authenticity and nonce.
  // let id_token = token_response
  //   .id_token()
  //   .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
  // let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;

  // // Verify the access token hash to ensure that the access token hasn't been substituted for
  // // another user's.
  // if let Some(expected_access_token_hash) = claims.access_token_hash() {
  //   let actual_access_token_hash = AccessTokenHash::from_token(
  //     token_response.access_token(),
  //     &id_token.signing_alg()?,
  //   )?;
  //   if actual_access_token_hash != *expected_access_token_hash {
  //     return Err(anyhow!("Invalid access token"));
  //   }
  // }

  // // The authenticated user's identity is now available. See the IdTokenClaims struct for a
  // // complete listing of the available claims.
  // println!(
  //   "User {} with e-mail address {} has authenticated successfully",
  //   claims.subject().as_str(),
  //   claims
  //     .email()
  //     .map(|email| email.as_str())
  //     .unwrap_or("<not provided>"),
  // );

  // // If available, we can use the UserInfo endpoint to request additional information.

  // // The user_info request uses the AccessToken returned in the token response. To parse custom
  // // claims, use UserInfoClaims directly (with the desired type parameters) rather than using the
  // // CoreUserInfoClaims type alias.
  // let userinfo: CoreUserInfoClaims = client
  //   .user_info(token_response.access_token().to_owned(), None)
  //   .map_err(|err| anyhow!("No user info endpoint: {:?}", err))?
  //   .request(http_client)
  //   .map_err(|err| anyhow!("Failed requesting user info: {:?}", err))?;

  // // See the OAuth2TokenResponse trait for a listing of other available fields such as
  // // access_token() and refresh_token().

  return Ok(());
}
