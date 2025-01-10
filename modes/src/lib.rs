use std::time::Instant;

use base::*;
use tfhe::boolean::prelude::*;

struct ECB {
    data: Vec<State>,
    keys: Vec<Key>,

}


impl ECB {
    pub fn new(data: &[State], keys: &[Key]) -> Self {
        ECB { data: data.to_vec(), keys: keys.to_vec() }
    }

    pub fn encrypt(&mut self, server_key: &ServerKey) {
        for state in self.data.iter_mut() {
            // Initial round key addition
            state.xor_key_enc(&self.keys[0], server_key);

            // Main rounds
            for round in 1..10 {
                let mut start = Instant::now();
                state.sub_bytes(server_key);
                println!("Sub Bytes Time Taken ROUND {:?} {:?}", round,  start.elapsed());
                start = Instant::now();
                state.shift_rows();
                println!("Shift Rows Time Taken ROUND {:?} {:?}", round,  start.elapsed());
                start = Instant::now();
                state.mix_columns(server_key);
                println!("Mix Columns Time Taken ROUND {:?} {:?}", round,  start.elapsed());
                start = Instant::now();
                state.xor_key_enc(&self.keys[round], server_key);
                println!("Xor Key Time Taken ROUND {:?} {:?}", round,  start.elapsed());
            }

            // Final round
            state.sub_bytes(server_key);
            state.shift_rows();
            state.xor_key_enc(&self.keys[10], server_key);
        }
    }

    pub fn decrypt(&mut self, server_key: &ServerKey) {
        for state in self.data.iter_mut() {
            // Initial round key addition
            state.xor_key_enc(&self.keys[10], server_key);

            // Main rounds
            for round in 1..10 {
                let mut start = Instant::now();
                state.inv_shift_rows();
                println!("Inv Shift Rows Time Taken ROUND {:?} {:?}", round, start.elapsed());
                start = Instant::now();
                state.inv_sub_bytes(server_key);
                println!("Inv Sub Bytes Time Taken ROUND {:?} {:?}", round, start.elapsed());
                start = Instant::now();
                state.xor_key_enc(&self.keys[10 - round], server_key);
                println!("Xor Key Time Taken ROUND {:?} {:?}", round, start.elapsed());
                start = Instant::now();
                state.inv_mix_columns(server_key);
                println!("Inv Mix Columns Time Taken ROUND {:?} {:?}", round, start.elapsed());
            }

            // Final round
            state.inv_shift_rows();
            state.inv_sub_bytes(server_key);
            state.xor_key_enc(&self.keys[0], server_key);
        }
    }

    pub fn to_states(&self) -> &Vec<State>{
        &self.data
    }
}


#[cfg(test)]

mod tests {
    use std::{time::Instant};

    use super::*;
    use tfhe::boolean::gen_keys;
    use base::primitive::*;
    use rayon::prelude::*;

    #[test]
    fn test_ecb() {
        const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);


        let curr_key = Key::from_u128_enc(0x2b28ab09_7eaef7cf_15d2154f_16a6883c , &client_key);
        let mut keys: Vec<_> = vec![curr_key.clone()];
        let states = [State::new(0x2b28ab09_7eaef7cf_15d2154f_16a6883c, &client_key)]; 

        let start = Instant::now();
        for i in 0..10 {
            let mut key = keys[i].clone();
            key.generate_next_key_in_place(&RCON[i], &server_key);
            keys.push(key);
        }

        let mut ecb = ECB::new(&states, &keys);

        println!("Key Expansion Time Taken {:?}", start.elapsed());   
        let start = Instant::now();
        with_server_key(|server_key| {
            ecb
            .encrypt(&server_key);  
        });
        println!("ENCRYPT TIME TAKEN {:?}", start.elapsed());

        let start = Instant::now();
        with_server_key(|server_key| {
            ecb
            .decrypt(&server_key);  
        });
        println!("DECRYPT TIME TAKEN {:?}", start.elapsed());

        let states = ecb.to_states();
        
        assert_eq!(states[0].decrypt_to_u128(&client_key), 0x2b28ab09_7eaef7cf_15d2154f_16a6883c)

    }
}