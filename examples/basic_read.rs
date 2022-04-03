use biscuit_auth::PublicKey;
use tower_biscuit_auth::BiscuitAuth;

fn main() {
    let auth = load_auth();
}

fn load_auth() -> BiscuitAuth {
    let policy = include_str!("policy.txt");

    let pubkey: Vec<u8> = hex::decode(include_str!("public.key")).unwrap();
    let pubkey = PublicKey::from_bytes(&pubkey).unwrap();

    BiscuitAuth::new(pubkey, policy).unwrap()
}
