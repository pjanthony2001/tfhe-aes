use std::time::Instant;

use base::*;
use tfhe::boolean::prelude::*;

pub struct ECB {
    keys: Vec<Key>,
}


impl ECB {
    pub fn new(keys: &[Key]) -> Self {
        ECB { keys: keys.to_vec() }
    }

    pub fn encrypt(&mut self, state: &mut State, server_key: &ServerKey) {
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

    pub fn decrypt(&mut self, state: &mut State, server_key: &ServerKey) {
        // Initial round key addition
        state.xor_key_enc(&self.keys[10], server_key);

        // Main rounds
        for round in 1..10 {
            let mut start = Instant::now();
            state.inv_shift_rows();
            println!("Inv Shift Rows Time Taken ROUND {:?} {:?}", round, start.elapsed());
            start = Instant::now();
            state.inv_sub_bytes(server_key);
            start = Instant::now();
            state.xor_key_enc(&self.keys[10 - round], server_key);
            start = Instant::now();
            state.inv_mix_columns(server_key);

        }

        // Final round
        state.inv_shift_rows();
        state.inv_sub_bytes(server_key);
        state.xor_key_enc(&self.keys[0], server_key);
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
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);


        let curr_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c , &client_key);
        let keys: Vec<_> = curr_key.generate_round_keys(&server_key).to_vec();  
        let mut state = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key); 

        let mut ecb = ECB::new(&keys);

        let start = Instant::now();
        with_server_key(|server_key| {
            ecb
            .encrypt(&mut state, &server_key);  
        });
        println!("ENCRYPT TIME TAKEN {:?}", start.elapsed());

        assert_eq!(state.decrypt_to_u128(&client_key), 0x3925841d_02dc09fb_dc118597_196a0b32);

        let start = Instant::now();
        with_server_key(|server_key| {
            ecb
            .decrypt(&mut state, &server_key);  
        });
        println!("DECRYPT TIME TAKEN {:?}", start.elapsed());
        
        assert_eq!(state.decrypt_to_u128(&client_key), 0x3243f6a8_885a308d_313198a2_e0370734)

    }
}