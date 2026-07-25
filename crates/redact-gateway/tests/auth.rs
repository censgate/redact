// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Integration tests for inbound authentication.

use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
use redact_gateway::auth::{
    build_authenticator, AllowAllAuthenticator, ApiKeyAuthenticator, AuthError, Authenticator,
};
use redact_gateway::config::{AuthMode, AuthSettings, OidcSettings};

fn bearer_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

#[tokio::test]
async fn api_key_accepts_configured_key() {
    let auth = ApiKeyAuthenticator::new(&[String::from("good-key")]);
    let ctx = auth
        .authenticate(&bearer_headers("good-key"))
        .await
        .unwrap();
    assert_eq!(ctx.mode, "api_key");
    assert_eq!(ctx.tenant, "default");
    let subject = ctx.subject.expect("subject");
    assert!(subject.starts_with("key:"));
    assert_eq!(subject.len(), 12);
}

#[tokio::test]
async fn api_key_rejects_unknown_key() {
    let auth = ApiKeyAuthenticator::new(&[String::from("good-key")]);
    let err = auth
        .authenticate(&bearer_headers("bad-key"))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::Invalid(_)));
}

#[tokio::test]
async fn api_key_missing_credential() {
    let auth = ApiKeyAuthenticator::new(&[String::from("good-key")]);
    let err = auth.authenticate(&HeaderMap::new()).await.unwrap_err();
    assert!(matches!(err, AuthError::Missing));
}

#[tokio::test]
async fn api_key_accepts_x_api_key_header() {
    let auth = ApiKeyAuthenticator::new(&[String::from("good-key")]);
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("good-key"));
    let ctx = auth.authenticate(&headers).await.unwrap();
    assert_eq!(ctx.mode, "api_key");
}

#[tokio::test]
async fn api_key_constant_time_handles_differing_lengths() {
    let auth = ApiKeyAuthenticator::new(&[String::from("ab")]);
    let err = auth
        .authenticate(&bearer_headers("a-completely-different-length-value"))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::Invalid(_)));
}

#[tokio::test]
async fn api_key_secret_never_leaks_into_context_or_debug() {
    let secret = "top-secret-api-key-value-do-not-leak";
    let auth = ApiKeyAuthenticator::new(&[String::from(secret)]);
    let ctx = auth.authenticate(&bearer_headers(secret)).await.unwrap();
    assert!(!format!("{auth:?}").contains(secret));
    assert!(!format!("{ctx:?}").contains(secret));
    assert!(!ctx.subject.as_ref().unwrap().contains(secret));
}

#[tokio::test]
async fn build_authenticator_none_is_allow_all() {
    let settings = AuthSettings {
        mode: AuthMode::None,
        api_keys: vec![],
        oidc: OidcSettings::default(),
    };
    let auth = build_authenticator(&settings).await.unwrap();
    assert_eq!(auth.mode(), "none");
    let ctx = auth.authenticate(&HeaderMap::new()).await.unwrap();
    assert_eq!(ctx.mode, "none");
}

#[tokio::test]
async fn allow_all_is_anonymous() {
    let auth = AllowAllAuthenticator;
    let ctx = auth.authenticate(&HeaderMap::new()).await.unwrap();
    assert_eq!(ctx.tenant, "default");
    assert!(ctx.subject.is_none());
    assert!(auth.ready().await);
}

#[cfg(feature = "oidc")]
mod oidc_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::routing::get;
    use axum::{Json, Router};
    use base64::Engine;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use redact_gateway::auth::OidcAuthenticator;
    use serde::Serialize;
    use serde_json::{json, Value};

    /// Test-only RSA private key (PKCS#8 PEM). Fixture — never used in production.
    const RSA_PRIVATE_PEM_1: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDnpn59SgdAxNQo
PxpsJpl8sEn26YDeVmwr5BHSI4IHk0PHFp83orl9a52CoDot1Ax65RvUrxbw4PEN
/nry0uQH1CiXrD52CBZMiTC5HI8xYTmCdQ91FGsGZT6xkUunGC9pZOX0ncs/k5A4
MFAwGCJYcV+a8D/hUpVkS9KdMZZKakr8BX/wuDmCxlWIZXbU//hk58NYDnpNN5+n
VAzxzj7C7+c43Gx4yj2sdierh5itl7uy012FPFyIUw7suRwRwDbHBwj2/Sdv2pyp
XYx1oUxycE3cQOwFgpF6Q/73IZ7v9eBosCDWOrYMl6u2eRc/nGoijCYJoedQxFDX
yZNoTiIfAgMBAAECggEAVlw/PtVI4/AdSg3Qe25efVo5kOgXh4w/kpNZw3ZCZTGV
LJU18WdkcKoclBTI68nohy5/1CgcTNwHchij3IAbzAFfyr/Hn3g/W/QvamuHxLiC
2KxsgVEF32ICX++TfS1qi4e2pR3opoCMXS5BztRIhaFqq5gSsJ15nWUZFUplxcKq
KrSWf6fWxEdLxikmtGCIXIPzAM0R4KLpt2umPECdm25nnCPa/MpO6jHaQkLKRr8P
uSpGcNGXrqthXxdRP1yuHfw2UD08glimiqa/v++S8E+3cyBCHjoNMQjo3db1PbV7
uutZP07G32T0oGNeCHkg3me99v+HZMJ5CO/E8YRMwQKBgQD4YaEO63lVblvPsXEv
3ULdMTk+yEDmdWa06/sx9kaDjGfGRNMjkidGrAZvMURH6Njq8fKW8voVdAjZJJJJ
94yriBT0dyzIcpi5v8ruxWzY7V+nmPLvQ3vLHk5ux1xue6W03ioYTkhmOI5YiKgb
0i/04rR9rI3A5/ByriJpAK1XQQKBgQDuwXzeUqWwndfHrtMofMSohXaaQ5NwdmEp
aCTXe+VXhAv3Puf1aXMMKWQ6Fl3cWUqgfXatBn1DPzItwDkh562MVs4zZ3kwAXkY
Z2SVJEUUtlHcYJ0+lHTfJh4lHGICp2fx6KJ/+LwtF6gx7zS+F3+WQ8U71jaSJnD9
k4SZuUOBXwKBgQCnsYqCvzqJElxMSlnH3hPhsPUcTSl8LvFr3xMWdVbARBBgTWFb
17ZKwaQKeHHINw4U+cs2XM+5okDDEizuYYMI4HR9ZOTIZI52gmXpdUN65jC5v8rs
/VvcFBcSNelS8oo7Je+3v0qkMTTx0znkprEYHeOMIe8GudGeK7ExwXJGwQKBgQDp
zC8qxmPZ/7c9osTD8Oni3E634VSP3Fxo38K0AG8ks/nDs6YRe6FdV2r+NsjS7d1W
K4X7CU/AejH4+zL3MJeRxa9GRx01FTwv2Y91PH8pOSAQXcudbGLF4d3DGXgggS4Y
hWYbSsd6oJ/jxgov23LlApgxcCMgGuSqa7p9jh28oQKBgGbb8UeYHcvn3ANBvO1S
XidGO5M0qp+8vRzbXe5yK1+yfb0yp1w5kyWS8a083ZFA+2adZf16J/tEWRn5XGI8
9EiTxJWioKaq+f5mMdB5brtx6XSVTgF+/Q+YFzpdO4UkmumYpHbDwx1gNJoBSKum
/59DvrbpZtbFNmiUrM0blO01
-----END PRIVATE KEY-----
"#;

    /// Second test-only RSA private key for rotation coverage. Fixture only.
    const RSA_PRIVATE_PEM_2: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClvQgsJkSmVWJY
Zt6momAodHS8R9oZMQd0voNOc+BRq9EZrTd2Rywqpj1oJ1c0+tNzzdLKKpVBghYo
NA69oaYxyIlS7FwsP8UT5Z6viUpN9Xq5l+NTuTCrSopCRNxKOiyUApeKcKS77ZAn
EHKV1NV/vCCwCKkapmsA3opyL+jsHilUs+nORkkEmi/npMsCIAuKF2PwE3nOnxcP
rqAV4FgSbeYk9iN71cFJfUyPUdqnFtCiw69JJMkWda9GLJXkFeyarRY+m4x/JtZh
ClDYbvYr6Tas+8JyckBxhEwrGzGvRL0Pc6A+7OKTGXVLt7ofaM4GhLCL/FZ8hD+M
QkJdKt4rAgMBAAECggEASLwJjx6IOBr2muciRSyzWG2rIUnDHBUZOZG2HELcKdtm
W4dZ9K1NY7Yq8r95FQYSsBqerBw9/k6xnJkj8vKy9dwU7/BMjxq5SX8WweBVXJsj
bbmLiR2Xj0SaInUH3AdlstrkWFwQ32xlO8+LCdgqjfEowzg5xjlMckg3p98AsEXj
Z6plFFgTnESE67IQUsDLX1lzwbp/oWeBVRtB+AV1qjAxAWnj02+nbRNely3dhMIx
aaqFM+u2kRI3lHE/gbjlvQpTFug7Vl3xzhlHMsvkwAPQB6WAqg614z9A+Q3JOjQa
JsnBmbR7vMGumj3tvfje3Yx7Uom0b/kvHPwftNw/wQKBgQDUyViXzHf95/FMJJCz
yFb58LKTNxNPDUEzNuFHgGIc8bIc6nBo2RUnjtBLo/Mq0pkrIMySORBr7VzZlx1f
mCWXkLAFWKmEXFWoRCoiPh0ZW9FiGY+n+IIt9zqSKgHYtBpngEHnjwdSyH2zBad9
/3EJIqwKFS9MpMhStSlw8h+dYQKBgQDHZa5JzX5dBIBcre4TGzEcWaok0TDunM8z
jKPyc7peV9cucdoAQ9HMYMKixzXOuDueKCDwslOgobBbydgJHZ+kG0zhLZ8yiy2b
IZMdczVNr8A+pPGI4O1gLKTRHgd7G3/jDLmb0TZTLIPbTcabPcD8OTQHSdC5QaZW
8B2JzSH7CwKBgA5hURBpLA7HtwHrUrAjsOURRDA4v6BPCAH7Cnx3i6njF6NmoJQl
X42d1CvYd52EP/+vJsQXASoaD3VRBhYoxRmaGJsz47jjOJK3kJVh1zuYfe0ARzoV
zE5o79di6V8IxOQLwehxPRB2JjCMCEa2laAFbNT9m4W1eShFv/g3FLXhAoGAeql2
ejhLz/UA8gKdPmuv3nzaSiPWMjOM021lPbUrpPXsjcnEDf2qhkvP8EsUMsLrCfQt
r2RERcCxuQWGPLVYi5+vv6ZNFM7Bk3koAynoVI4VeXQGkemsnUlZartKZtUX6xjc
5ZniDXCI/NPvpXhry7104Dbsi8pzBXBY+3iRutkCgYBf8Dek9mUK7tl49+c9IyrN
bZ8Qvh2m30Biluqhw8gQ2mBw2El+/qZnx9ThNKshScHDHOUAzI2pqUdvNIdIFUel
Bf+6wY24Tr5v26VMLeGhf7IUO1CfGkkGXnJZLF9CIF7w7VFJNjar9AgZh+j53kJk
5Ma9ZcEwIi1YSVxiTimCEQ==
-----END PRIVATE KEY-----
"#;

    #[derive(Clone)]
    struct MockIssuer {
        addr: SocketAddr,
        keys: Arc<Mutex<Value>>,
    }

    impl MockIssuer {
        fn issuer(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn set_keys(&self, keys: Vec<Value>) {
            *self.keys.lock().unwrap() = json!({ "keys": keys });
        }
    }

    async fn spawn_mock_issuer(initial_keys: Vec<Value>) -> MockIssuer {
        let keys = Arc::new(Mutex::new(json!({ "keys": initial_keys })));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let jwks_uri = format!("{issuer}/jwks");

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let issuer = issuer.clone();
                    let jwks_uri = jwks_uri.clone();
                    move || {
                        let issuer = issuer.clone();
                        let jwks_uri = jwks_uri.clone();
                        async move {
                            Json(json!({
                                "issuer": issuer,
                                "jwks_uri": jwks_uri,
                            }))
                        }
                    }
                }),
            )
            .route(
                "/jwks",
                get({
                    let keys = keys.clone();
                    move || {
                        let keys = keys.clone();
                        async move { Json(keys.lock().unwrap().clone()) }
                    }
                }),
            );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::task::yield_now().await;

        MockIssuer { addr, keys }
    }

    fn encoding_key(pem: &str) -> EncodingKey {
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("fixture pem")
    }

    fn public_jwk(pem: &str, kid: &str) -> Value {
        let key = encoding_key(pem);
        let mut jwk = Jwk::from_encoding_key(&key, Algorithm::RS256).expect("jwk from key");
        jwk.common.key_id = Some(kid.to_string());
        serde_json::to_value(jwk).unwrap()
    }

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iss: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        exp: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scp: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tid: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tenant: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn mint(pem: &str, kid: &str, claims: &Claims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &encoding_key(pem)).expect("encode jwt")
    }

    fn base_claims(issuer: &str) -> Claims {
        Claims {
            sub: "user-123".to_string(),
            iss: issuer.to_string(),
            aud: Some("gateway".to_string()),
            exp: now() + 3600,
            nbf: Some(now() - 10),
            scope: Some("openid gateway.read".to_string()),
            scp: None,
            tid: Some("tenant-a".to_string()),
            tenant: None,
            profile: Some("strict".to_string()),
        }
    }

    fn oidc_settings(issuer: &str) -> OidcSettings {
        OidcSettings {
            issuer: Some(issuer.to_string()),
            audience: Some("gateway".to_string()),
            jwks_url: None,
            required_scopes: vec!["gateway.read".to_string()],
            tenant_claim: None,
            profile_claim: Some("profile".to_string()),
            jwks_refresh_secs: 300,
            leeway_secs: 60,
        }
    }

    fn base64_url_encode(input: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
    }

    #[tokio::test]
    async fn oidc_accepts_valid_token() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let token = mint(
            RSA_PRIVATE_PEM_1,
            "test-key-1",
            &base_claims(&mock.issuer()),
        );
        let ctx = auth.authenticate(&bearer_headers(&token)).await.unwrap();
        assert_eq!(ctx.mode, "oidc");
        assert_eq!(ctx.subject.as_deref(), Some("user-123"));
        assert_eq!(ctx.tenant, "tenant-a");
        assert_eq!(ctx.profile.as_deref(), Some("strict"));
        assert!(ctx.scopes.iter().any(|s| s == "gateway.read"));
        assert!(auth.ready().await);
    }

    #[tokio::test]
    async fn oidc_rejects_wrong_issuer() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let mut claims = base_claims(&mock.issuer());
        claims.iss = "http://evil.example".to_string();
        let token = mint(RSA_PRIVATE_PEM_1, "test-key-1", &claims);
        let err = auth
            .authenticate(&bearer_headers(&token))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn oidc_rejects_wrong_audience() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let mut claims = base_claims(&mock.issuer());
        claims.aud = Some("other-audience".to_string());
        let token = mint(RSA_PRIVATE_PEM_1, "test-key-1", &claims);
        let err = auth
            .authenticate(&bearer_headers(&token))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn oidc_rejects_expired_token() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let mut claims = base_claims(&mock.issuer());
        claims.exp = now() - 120;
        let token = mint(RSA_PRIVATE_PEM_1, "test-key-1", &claims);
        let err = auth
            .authenticate(&bearer_headers(&token))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn oidc_rejects_unknown_signing_key() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let token = mint(
            RSA_PRIVATE_PEM_2,
            "test-key-2",
            &base_claims(&mock.issuer()),
        );
        let err = auth
            .authenticate(&bearer_headers(&token))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn oidc_rejects_alg_none() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let header = base64_url_encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64_url_encode(
            json!({
                "sub": "user-123",
                "iss": mock.issuer(),
                "aud": "gateway",
                "exp": now() + 3600,
                "scope": "openid gateway.read",
            })
            .to_string()
            .as_bytes(),
        );
        let token = format!("{header}.{payload}.");
        let err = auth
            .authenticate(&bearer_headers(&token))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn oidc_missing_required_scope() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let mut claims = base_claims(&mock.issuer());
        claims.scope = Some("openid".to_string());
        let token = mint(RSA_PRIVATE_PEM_1, "test-key-1", &claims);
        let err = auth
            .authenticate(&bearer_headers(&token))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InsufficientScope(_)));
    }

    #[tokio::test]
    async fn oidc_surfaces_tenant_and_profile_claims() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let mut settings = oidc_settings(&mock.issuer());
        settings.tenant_claim = Some("tenant".to_string());
        let auth = OidcAuthenticator::new(&settings).unwrap();

        let mut claims = base_claims(&mock.issuer());
        claims.tid = None;
        claims.tenant = Some("from-tenant-claim".to_string());
        claims.profile = Some("hipaa".to_string());
        let token = mint(RSA_PRIVATE_PEM_1, "test-key-1", &claims);
        let ctx = auth.authenticate(&bearer_headers(&token)).await.unwrap();
        assert_eq!(ctx.tenant, "from-tenant-claim");
        assert_eq!(ctx.profile.as_deref(), Some("hipaa"));
    }

    #[tokio::test]
    async fn oidc_refreshes_jwks_on_kid_miss_after_rotation() {
        let jwk1 = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk1]).await;
        let auth = OidcAuthenticator::new(&oidc_settings(&mock.issuer())).unwrap();

        let token1 = mint(
            RSA_PRIVATE_PEM_1,
            "test-key-1",
            &base_claims(&mock.issuer()),
        );
        auth.authenticate(&bearer_headers(&token1)).await.unwrap();

        let jwk2 = public_jwk(RSA_PRIVATE_PEM_2, "test-key-2");
        mock.set_keys(vec![jwk2]);

        let token2 = mint(
            RSA_PRIVATE_PEM_2,
            "test-key-2",
            &base_claims(&mock.issuer()),
        );
        let ctx = auth.authenticate(&bearer_headers(&token2)).await.unwrap();
        assert_eq!(ctx.subject.as_deref(), Some("user-123"));
    }

    #[tokio::test]
    async fn oidc_build_authenticator_wires_mode() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let settings = AuthSettings {
            mode: AuthMode::Oidc,
            api_keys: vec![],
            oidc: oidc_settings(&mock.issuer()),
        };
        let auth = build_authenticator(&settings).await.unwrap();
        assert_eq!(auth.mode(), "oidc");
    }

    #[tokio::test]
    async fn oidc_explicit_jwks_url_skips_discovery_path_for_keys() {
        let jwk = public_jwk(RSA_PRIVATE_PEM_1, "test-key-1");
        let mock = spawn_mock_issuer(vec![jwk]).await;
        let mut settings = oidc_settings(&mock.issuer());
        settings.jwks_url = Some(format!("{}/jwks", mock.issuer()));
        let auth = OidcAuthenticator::new(&settings).unwrap();
        let token = mint(
            RSA_PRIVATE_PEM_1,
            "test-key-1",
            &base_claims(&mock.issuer()),
        );
        auth.authenticate(&bearer_headers(&token)).await.unwrap();
    }
}
