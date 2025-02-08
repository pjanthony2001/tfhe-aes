use std::time::Instant;

use base::*;
use rayon::vec;
use tfhe::boolean::prelude::*;
use crate::ecb::ECB;  


/// CBC mode is counter mode for AES-128
/// 
/// 
/// 
/// 


struct OFB {
    ecb: ECB,
    iv: State,
    n: u8
}

impl OFB {
    pub fn new(keys: &[Key], iv: State, n: u8) -> Self {
        OFB { ecb: ECB::new(keys), iv, n }
    }

    pub fn encrypt(&mut self, plaintext: &[State], server_key: &ServerKey) -> Vec<State> {
        let mut result = plaintext.to_vec();
        let mut curr_state = self.iv.clone();

        for i in 0..self.n {
            self.ecb.encrypt(&mut curr_state, server_key);
            result[i as usize].xor_state(&curr_state, server_key);
        }   

        result
    }

    pub fn decrypt(&mut self, ciphertexts: &[State], server_key: &ServerKey) -> Vec<State>{
        let mut result = ciphertexts.to_vec();
        let mut curr_state = self.iv.clone();

        for i in 0..self.n {
            self.ecb.encrypt(&mut curr_state, server_key);
            result[i as usize].xor_state(&curr_state, server_key);
        }   

        result
    }
}

