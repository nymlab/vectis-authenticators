use cosmwasm_std::{Event, Response, StdError};
use cw2::{get_contract_version, set_contract_version, ContractVersion};
use sylvia::{
    contract, schemars,
    types::{InstantiateCtx, QueryCtx},
};

// Vectis lib
use vectis_wallet::{
    interface::{authenticator_trait, AuthenticatorTrait},
    types::error::AuthenticatorError,
};

/// verification lib
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::PublicKey;
use sha2::{Digest, Sha256};

// webauthn types and decoding
use crate::types::CollectedClientData;
use base64ct::Encoding;

#[cfg(not(feature = "library"))]
use sylvia::entry_points;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Webauthn {}

pub(crate) fn de_client_data(data: &[u8]) -> Result<CollectedClientData, AuthenticatorError> {
    serde_json_wasm::from_slice(data)
        .map_err(|_| AuthenticatorError::DecodeData("client_data".into()))
}

pub(crate) fn hash_to_base64url_string(data: &[u8]) -> String {
    base64ct::Base64UrlUnpadded::encode_string(Sha256::digest(data).as_slice())
}

mod auth_trait {
    use super::*;

    #[contract(module=crate::contract)]
    #[messages(authenticator_trait as AuthenticatorTrait)]
    impl AuthenticatorTrait for Webauthn {
        type Error = AuthenticatorError;

        #[msg(query)]
        fn authenticate(
            &self,
            _ctx: QueryCtx,
            signed_data: Vec<u8>,
            controller_data: Vec<u8>,
            // metadata: [auth_data, client_data]
            metadata: Vec<Vec<u8>>,
            signature: Vec<u8>,
        ) -> Result<bool, Self::Error> {
            // First: we check if the signed data contains the msgs we have been told to execute

            let client_data = de_client_data(&metadata[1])?;

            // the signed challenge should be the hash of the hash of `SignDoc`
            let expected_hash_string = hash_to_base64url_string(&signed_data);
            if client_data.challenge != expected_hash_string {
                return Err(AuthenticatorError::InvalidChallenge);
            }

            // Second: we can verify the signature
            //
            // https://w3c.github.io/webauthn/#sctn-signature-attestation-types
            // Convert signature from ASN.1 sequence to "raw" format
            let verify_signature = DerSignature::from_bytes(&signature)
                .map_err(|e| AuthenticatorError::SignatureParse(e.to_string()))?;

            let pub_key = PublicKey::from_sec1_bytes(&controller_data)
                .map_err(|e| AuthenticatorError::PubKeyParse(e.to_string()))?;

            let verifier = VerifyingKey::from(&pub_key);
            // The data that should have been signed
            // This includes the msg we verified in the first step
            let auth_data = &metadata[0];
            let client_data_hash = Sha256::digest(&metadata[1]);
            let auth_signed_data = [auth_data.as_slice(), client_data_hash.as_ref()].concat();
            let result = verifier.verify(&auth_signed_data, &verify_signature);

            Ok(result.is_ok())
        }

        #[msg(query)]
        fn contract_version(&self, ctx: QueryCtx) -> Result<ContractVersion, StdError> {
            get_contract_version(ctx.deps.storage)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_points)]
#[contract]
#[error(AuthenticatorError)]
#[messages(authenticator_trait as AuthenticatorTrait)]
impl Webauthn {
    pub const fn new() -> Self {
        Self {}
    }

    #[msg(instantiate)]
    fn instantiate(&self, ctx: InstantiateCtx) -> Result<Response, AuthenticatorError> {
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
        let event = self.get_event("instantiate");
        Ok(Response::new().add_event(event))
    }

    pub(crate) fn get_event(&self, action: impl Into<String>) -> Event {
        Event::new("vectis.webauthn.v1").add_attribute("action", action)
    }
}
