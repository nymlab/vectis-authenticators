use asn1::ParseError;
use cosmwasm_std::{from_binary, to_binary, Binary, Event, Response};
use cw2::set_contract_version;
use sylvia::types::QueryCtx;
use sylvia::{contract, schemars, types::InstantiateCtx};

// Vectis lib
use vectis_wallet::{
    authenicator_export,
    authenicator_export::{AuthenicatorExport, AuthenticatorError},
    VectisRelayedTx, WebauthnRelayedTxMsg,
};

// verification lib
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;
use ripemd160::Digest as Ripemd160Digest;
use sha2::Sha256;

// webauthn types
//use crate::types::CollectedClientData;

#[cfg(not(feature = "library"))]
use sylvia::entry_points;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Webauthn {}

#[contract]
#[messages(authenicator_export as AuthenicatorExport)]
impl AuthenicatorExport for Webauthn {
    type Error = AuthenticatorError;
    type MsgType = WebauthnRelayedTxMsg;

    #[msg(query)]
    fn authenticate(
        &self,
        _ctx: QueryCtx,
        signed_data: VectisRelayedTx,
        controller_data: Binary,
        /// metadata: [auth_data, client_data]
        metadata: Vec<Binary>,
        signature: Binary,
    ) -> Result<bool, Self::Error> {
        // ---------------------
        // First: we check if the signed data contains the msgs we have been told to execute
        // ---------------------
        //let client_data: CollectedClientData =
        //    from_binary(&metadata[1]).map_err(|_| AuthenticatorError::DecodeClientData)?;
        //// the signed challenge should be the hash of the string of the `VectisRelayTx` type
        //let tx_string =
        //    serde_json_wasm::to_string(&signed_data).map_err(|_| AuthenticatorError::Serde)?;
        //// we can do lossy here as it will just no match in the next step if it fails to convert
        //let expected_hash_string =
        //    String::from_utf8_lossy(Sha256::digest(tx_string.as_bytes()).as_slice()).to_string();
        //if client_data.challenge != expected_hash_string {
        //    return Err(AuthenticatorError::InvalidChallenge);
        //}

        // -------------------
        // Second: we can verify the signature
        // -------------------
        // https://w3c.github.io/webauthn/#sctn-signature-attestation-types
        // Convert signature from ASN.1 sequence to "raw" format
        let raw_signature = asn1::parse(&signature, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let r = d.read_element::<&[u8]>()?;
                let s = d.read_element::<&[u8]>()?;
                let raw = Vec::from([r, s].concat());
                return Ok(raw);
            });
        })
        .map_err(|e: ParseError| AuthenticatorError::SignatureParse(e.to_string()))?;
        let raw_signature = vec![1, 2, 3];

        //let verify_signature = Signature::from_slice(&raw_signature)
        //    .map_err(|e| AuthenticatorError::SignatureParse(e.to_string()))?;
        //let pub_key = PublicKey::from_sec1_bytes(&controller_data)
        //    .map_err(|e| AuthenticatorError::PubKeyParse(e.to_string()))?;
        //let verifier = VerifyingKey::from(&pub_key);
        //let auth_data = &metadata[0];
        //// The data that should have been signed
        //// This includes the msg we verified in the first step
        //let client_data_hash = Sha256::digest(&metadata[1]);
        //let auth_signed_data = [auth_data.as_slice(), client_data_hash.as_ref()].concat();
        //let result = verifier.verify(&auth_signed_data, &verify_signature);

        //Ok(result.is_ok())
        Ok(true)
    }
}

#[cfg_attr(not(feature = "library"), entry_points)]
#[contract]
#[error(AuthenticatorError)]
#[messages(authenicator_export as AuthenticatorExport)]
impl Webauthn {
    pub const fn new() -> Self {
        Self {}
    }

    #[msg(instantiate)]
    fn instantiate(&self, ctx: InstantiateCtx) -> Result<Response, AuthenticatorError> {
        set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
        let event = Event::new("vectis.webauthn.v1");
        Ok(Response::new().add_event(event))
    }
}
