use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use josekit::{
    JoseHeader,
    jws::{JwsHeader, JwsSigner},
};
use serde::{Serialize, de::DeserializeOwned};

pub trait JwtCreator: Serialize + DeserializeOwned {
    type Header: JoseHeader;
    fn create_jwt(
        &self,
        header: &Self::Header,
        issuer: &str,
        lifetime: chrono::Duration,
        signer: &dyn JwsSigner,
    ) -> String;
}

impl<T> JwtCreator for T
where
    T: Serialize + DeserializeOwned,
{
    type Header = JwsHeader;

    fn create_jwt(
        &self,
        header: &Self::Header,
        issuer: &str,
        lifetime: chrono::Duration,
        signer: &dyn JwsSigner,
    ) -> String {
        let mut val = serde_json::to_value(self).unwrap();
        let now = Utc::now();
        val["iss"] = serde_json::Value::String(issuer.to_string());
        val["iat"] = serde_json::Value::Number(now.timestamp().into());
        // account for clock skew
        val["nbf"] = serde_json::Value::Number((now - Duration::minutes(5)).timestamp().into());
        val["exp"] = serde_json::Value::Number((now + lifetime).timestamp().into());
        let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&val).unwrap());
        let header = BASE64_URL_SAFE_NO_PAD.encode(header.to_string());
        let mut jwt = format!("{}.{}", header, payload);
        let signature = BASE64_URL_SAFE_NO_PAD.encode(signer.sign(jwt.as_bytes()).unwrap());
        jwt.push_str(".");
        jwt.push_str(&signature);
        jwt
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::jwt::{Jwt, verifier::DefaultVerifier};

    use super::*;
    use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256;
    use serde::Deserialize;

    #[test]
    fn test_create_jwt() {
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        header.set_token_type("example+jwt");
        let signer_key = Es256.generate_key_pair().unwrap();
        let signer = Es256
            .signer_from_der(signer_key.to_der_private_key())
            .unwrap();
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestStruct {
            id: String,
            name: String,
        }

        let jwt = TestStruct {
            id: "1".to_string(),
            name: "John".to_string(),
        }
        .create_jwt(&header, "test-issuer", Duration::minutes(5), &signer);

        println!("{jwt}");
        let parsed_jwt = Jwt::<TestStruct>::from_str(&jwt).unwrap();
        let verifier = Es256
            .verifier_from_der(signer_key.to_der_public_key())
            .unwrap();
        let payload = parsed_jwt
            .payload_with_verifier(
                &verifier,
                &DefaultVerifier::new("example+jwt".to_string(), vec![]),
            )
            .unwrap();
        assert_eq!(
            payload,
            &TestStruct {
                id: "1".to_string(),
                name: "John".to_string(),
            }
        );
    }
}
