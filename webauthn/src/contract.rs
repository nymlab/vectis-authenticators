use cosmwasm_std::{Event, Response, StdError};
use cw2::{get_contract_version, set_contract_version, ContractVersion};
use sylvia::{
    contract, schemars,
    types::{InstantiateCtx, QueryCtx},
};

use dchain_interfaces::abstractaccount::{
    interface::{authenticator_trait, AuthenticatorTrait},
    types::error::AuthenticatorError,
    util::webauthn::{de_client_data, to_base64url_string},
};

/// verification lib
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::PublicKey;
use sha2::{Digest, Sha256};

#[cfg(not(feature = "library"))]
use sylvia::entry_points;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Webauthn {}

pub mod auth_trait {
    use super::*;

    #[contract(module=crate::contract)]
    #[sv::messages(authenticator_trait as AuthenticatorTrait)]
    impl AuthenticatorTrait for Webauthn {
        type Error = AuthenticatorError;

        #[sv::msg(query)]
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

            // NOTE: passkey client base64url encoding of the input challenge before signing
            //
            // We preveriously used hash_to_base64url_string to preserve the original message,
            // (to decode into CosmosMsg),
            // before but we do not need to do that anymore.
            // This `signed_data` is just the txBytes from `sign_doc`
            let expected_hash_string = to_base64url_string(&signed_data);
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

        #[sv::msg(query)]
        fn contract_version(&self, ctx: QueryCtx) -> Result<ContractVersion, StdError> {
            get_contract_version(ctx.deps.storage)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_points)]
#[contract]
#[sv::error(AuthenticatorError)]
#[sv::messages(authenticator_trait as AuthenticatorTrait)]
impl Webauthn {
    pub const fn new() -> Self {
        Self {}
    }

    #[sv::msg(instantiate)]
    fn instantiate(&self, ctx: InstantiateCtx) -> Result<Response, AuthenticatorError> {
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
        let event = self.get_event("instantiate");
        Ok(Response::new().add_event(event))
    }

    pub(crate) fn get_event(&self, action: impl Into<String>) -> Event {
        Event::new("vectis.webauthn.v1").add_attribute("action", action)
    }
}
