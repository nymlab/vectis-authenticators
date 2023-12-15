use cosmwasm_schema::write_api;

use vectis_webauthn_authenticator::contract::sv::{
    ContractExecMsg, ContractQueryMsg, InstantiateMsg,
};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ContractExecMsg,
        query: ContractQueryMsg,
    }
}
