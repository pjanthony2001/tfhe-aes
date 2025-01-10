use tfhe::boolean::prelude::*;
use tfhe::boolean::gen_keys;
use std::time::Instant;

fn main() {
    let (client_key, server_key) = gen_keys();

    let a = client_key.encrypt(true);
    let b = client_key.encrypt(false);
    let c = client_key.encrypt(true);

    // 5. Apply PBS with a timer
    let start_time = Instant::now();
    let result = server_key.mux(&a, &b, &c);
    let duration = start_time.elapsed();


    // 6. Decrypt result
    let decrypted_result = client_key.decrypt(&result);
    println!("Decrypted result: {}", decrypted_result);
    println!("Lookup Table PBS Time: {:?}", duration);
}
