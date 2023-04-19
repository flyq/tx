use ethers::{
    core::types::{Address, Signature, TransactionRequest},
    providers::{Http, Middleware, Provider},
    types::U256,
};
use eyre::Result;
use libsecp256k1::{Message, PublicKey, SecretKey};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

#[tokio::main]
async fn main() -> Result<()> {
    let private_key = SecretKey::parse_slice(
        &hex::decode("32e890da68f49d9be6d3642b2a1163fd8233cf995e9766a459d4cb5545913faa")
            .expect("err hex"),
    )
    .expect("err private key");
    println!("private key: {:?}", hex::encode(&private_key.serialize()));

    let public_key = PublicKey::from_secret_key(&private_key);
    println!("public key: {:?}", hex::encode(&public_key.serialize()));

    let mut output = [0u8; 32];

    let mut hasher = Keccak::v256();
    hasher.update(&public_key.serialize()[1..]);
    hasher.finalize(&mut output);

    let sender = Address::from_slice(&output[12..]);

    println!("sender address: {:?}", sender);

    let provider =
        Provider::<Http>::try_from("https://goerli.infura.io/v3/e65f012a4dcb40f09fbcfccb10a355d8")?;

    let to = Address::from_str("0xbd70d89667A3E1bD341AC235259c5f2dDE8172A9").unwrap();

    let gas_price = provider.get_gas_price().await?;
    println!("gas_price: {:}", gas_price);
    let balance = provider.get_balance(sender, None).await?;

    let tx = TransactionRequest::new()
        .to(to)
        .gas(21000)
        .value(balance - gas_price * 21000)
        .gas_price(gas_price)
        .chain_id(5)
        .nonce(1);

    let tx_sign_hash = tx.sighash();
    let msg = Message::parse_slice(tx_sign_hash.as_bytes()).expect("error msg");

    let (sign, reid) = libsecp256k1::sign(&msg, &private_key);
    let recovery_id: u64 = u64::from(reid.serialize()) + 35 + 2 * 5;

    let signature = Signature {
        r: U256::from(sign.r.b32()),
        s: U256::from(sign.s.b32()),
        v: recovery_id,
    };

    let bytes = tx.rlp_signed(&signature);

    let tx_rec = provider.send_raw_transaction(bytes).await?.await?;

    println!("receipt: {:?}", tx_rec);

    Ok(())
}
