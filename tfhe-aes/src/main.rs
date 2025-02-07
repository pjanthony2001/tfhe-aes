use tfhe::boolean::prelude::*;
use tfhe::boolean::gen_keys;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use rayon::prelude::*;
use dashmap::DashMap;

fn main() {
    let (client_key, server_key) = gen_keys();

    let a = client_key.encrypt(true);
    let b = client_key.encrypt(false);
    let c = client_key.encrypt(true);

    let dashmap: DashMap<u8, Ciphertext> = DashMap::new();
    let mut hashmap: HashMap<u8, Ciphertext> = HashMap::new();

    dashmap.insert(0, a.clone());
    dashmap.insert(1, b.clone());
    dashmap.insert(2, c.clone());


    hashmap.insert(0, a);
    hashmap.insert(1, b);
    hashmap.insert(2, c);


    let start_time = Instant::now();
    let next_hashmap: HashMap<_, _>= (0..255).map(|x| {
        let a = hashmap.get(&0).unwrap();
        let b = hashmap.get(&1).unwrap();
        let c = hashmap.get(&2).unwrap();

        (x, a, b, c)
    }).collect::<Vec<_>>()
    
    .into_par_iter().map_with(server_key, |server_key, (x, a, b, c)| {

        (x, server_key.mux(&a, &b, &c))
    
    }).collect();

    let a = next_hashmap.get(&1);

    let duration = start_time.elapsed();
    println!("Time per task: {:?}", duration / (255));

    //TODO: write the general operation function that takes a boolean obj and a hashmap and then converts it to an executable function. 
    // Should to straight to collect, seems like I can get up to 18ms if I don't use dashmap to try to make it more complex
    // simplify there are 133 * 18  ms per stage, so should be < 2s per byte subst 
    // which means up to lower than 16s for the whole 16 bytes. which is a majority of our time. 

    // documentation next OOOF
    // then we can start working on the actual AES implementation.  



}
