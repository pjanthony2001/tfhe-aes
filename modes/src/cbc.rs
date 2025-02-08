use std::time::Instant;

use base::*;
use rayon::vec;
use tfhe::boolean::prelude::*;
use crate::ecb::{self, ECB};  


/// CBC mode is counter mode for AES-128
/// 
/// 
/// 
/// 


struct CBC {
    ecb: ECB,
    iv: State,
    n: u8
}

impl CBC {
    pub fn new(keys: &[Key], iv: State, n: u8) -> Self {
        CBC { ecb: ECB::new(keys), iv, n }
    }

    pub fn encrypt(&mut self, plaintext: &[State], server_key: &ServerKey) -> Vec<State> {
        let mut result = plaintext.to_vec();
        result[0].xor_state(&self.iv, server_key);
        self.ecb.encrypt(&mut result[0], server_key); // Encrypt the first block

        for i in 1..self.n {
            let prev_state = result[(i - 1) as usize].clone();
            result[i as usize].xor_state(&prev_state, server_key);
            self.ecb.encrypt(&mut result[i as usize], server_key);
        }   

        result
    }

    pub fn decrypt(&mut self, ciphertexts: &[State], server_key: &ServerKey) -> Vec<State>{
        let mut result = ciphertexts.to_vec();

        for i in (1..self.n).rev() {
            self.ecb.decrypt(&mut result[i as usize], server_key);
            let prev_state = result[(i - 1) as usize].clone();
            result[i as usize].xor_state(&prev_state, server_key);
        }   

        self.ecb.decrypt(&mut result[0], server_key);
        result[0].xor_state(&self.iv, server_key); 
        result
    }
}

