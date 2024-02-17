use crate::{contract::*, types::*};
use cosmwasm_std::testing::{mock_dependencies, mock_env};
use ptd_wallet::{interface::AuthenticatorTrait, types::wallet::WebauthnCredData};
use sylvia::types::QueryCtx;

const PUB_KEY_BYTES: [u8; 65] = [
    4, 254, 213, 81, 121, 242, 209, 178, 171, 160, 209, 220, 243, 199, 156, 57, 7, 187, 116, 219,
    198, 101, 89, 52, 55, 116, 76, 44, 30, 67, 0, 143, 189, 75, 244, 25, 219, 51, 204, 90, 94, 118,
    253, 230, 111, 25, 66, 150, 185, 16, 177, 143, 185, 58, 174, 105, 199, 187, 209, 50, 112, 128,
    88, 201, 199,
];

const COSMOS_MSG: [u8; 147] = [
    123, 34, 109, 101, 115, 115, 97, 103, 101, 115, 34, 58, 91, 123, 34, 98, 97, 110, 107, 34, 58,
    123, 34, 115, 101, 110, 100, 34, 58, 123, 34, 97, 109, 111, 117, 110, 116, 34, 58, 91, 123, 34,
    100, 101, 110, 111, 109, 34, 58, 34, 117, 106, 117, 110, 111, 120, 34, 44, 34, 97, 109, 111,
    117, 110, 116, 34, 58, 34, 49, 48, 34, 125, 93, 44, 34, 116, 111, 95, 97, 100, 100, 114, 101,
    115, 115, 34, 58, 34, 106, 117, 110, 111, 49, 113, 99, 54, 99, 113, 50, 108, 115, 100, 48, 118,
    99, 99, 99, 101, 117, 112, 115, 55, 51, 97, 117, 100, 100, 116, 117, 50, 112, 54, 112, 121,
    109, 119, 100, 54, 117, 115, 104, 34, 125, 125, 125, 93, 44, 34, 110, 111, 110, 99, 101, 34,
    58, 48, 125,
];

const CLIENT_DATA: [u8; 143] = [
    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110, 46, 103, 101,
    116, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34, 90, 71, 87, 84, 81, 66,
    48, 116, 116, 81, 72, 112, 114, 83, 68, 121, 117, 121, 97, 118, 81, 118, 70, 76, 107, 116, 79,
    77, 109, 97, 85, 97, 121, 85, 103, 112, 52, 112, 97, 77, 72, 122, 107, 34, 44, 34, 111, 114,
    105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 112, 97, 115, 115, 107,
    101, 121, 45, 112, 111, 99, 46, 118, 101, 114, 99, 101, 108, 46, 97, 112, 112, 34, 44, 34, 99,
    114, 111, 115, 115, 79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
];

const AUTH_DATA: [u8; 37] = [
    160, 69, 228, 49, 29, 7, 49, 76, 44, 221, 70, 108, 153, 137, 118, 53, 175, 165, 26, 158, 250,
    12, 31, 58, 208, 251, 254, 192, 151, 172, 43, 29, 1, 0, 0, 0, 0,
];

const ASN1SIG: [u8; 72] = [
    48, 70, 2, 33, 0, 239, 139, 59, 204, 38, 219, 76, 13, 81, 227, 244, 206, 106, 106, 82, 233,
    224, 66, 106, 231, 148, 119, 165, 59, 129, 5, 37, 86, 23, 26, 127, 230, 2, 33, 0, 245, 7, 2,
    167, 86, 219, 132, 126, 6, 203, 61, 98, 248, 2, 14, 132, 111, 193, 212, 143, 212, 201, 248,
    197, 239, 30, 189, 97, 112, 61, 42, 195,
];

fn get_controller_data() -> Vec<u8> {
    PUB_KEY_BYTES.to_vec()
}

#[test]
fn it_de_client_data_correctly() {
    let client_data = de_client_data(&CLIENT_DATA).unwrap();
    let challenge = client_data.challenge;
    assert_eq!(challenge, to_base64url_string(&COSMOS_MSG))
}

#[test]
fn it_verifies() {
    let contract = Webauthn::new();
    let deps = mock_dependencies();
    let ctx = QueryCtx {
        deps: deps.as_ref(),
        env: mock_env(),
    };
    let result = contract
        .authenticate(
            ctx,
            COSMOS_MSG.to_vec(),
            get_controller_data(),
            vec![AUTH_DATA.to_vec(), CLIENT_DATA.to_vec()],
            ASN1SIG.to_vec(),
        )
        .unwrap();
    assert!(result)
}

#[test]
fn it_does_not_verify_wrong_auth_data() {
    let contract = Webauthn::new();
    let deps = mock_dependencies();
    let ctx = QueryCtx {
        deps: deps.as_ref(),
        env: mock_env(),
    };

    let mut wrong_hash = AUTH_DATA.to_vec();
    wrong_hash.swap(15, 18);

    let result = contract
        .authenticate(
            ctx,
            COSMOS_MSG.to_vec(),
            get_controller_data(),
            vec![wrong_hash, CLIENT_DATA.to_vec()],
            ASN1SIG.to_vec(),
        )
        .unwrap();
    assert!(!result)
}
