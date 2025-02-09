use base::*;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;
use crate::ecb::ECB;  


/// CTR mode is the counter mode for AES-128
/// 
/// As there is no way to randomly generate the counter in the FHE context, we have to pass it as an argument.
/// As such, we generate the counters, encrypt, and then pass them to the CTR. 


pub struct CTR {
    ecb: ECB,
    counters: Vec<State>,
    n: u8
}

impl CTR {
    pub fn new(keys: &[Key], counters: &[State], n: u8) -> Self {
        CTR { ecb: ECB::new(keys), counters: counters.to_vec(), n }
    }

    pub fn encrypt(&self, plaintext: &mut [State], server_key: &ServerKey) {
        let mut enc_counters = self.counters.to_vec();
        enc_counters.par_iter_mut().for_each(|x| self.ecb.encrypt(x, server_key));
        plaintext.par_iter_mut().zip(enc_counters.par_iter()).for_each_with(server_key, |server_key, (x, y)| x.xor_state(y, server_key));
    }

    pub fn decrypt(&self, ciphertexts: &mut [State], server_key: &ServerKey) {
        let mut enc_counters = self.counters.to_vec();
        enc_counters.par_iter_mut().for_each(|x| self.ecb.encrypt(x, server_key));
        ciphertexts.par_iter_mut().zip(enc_counters.par_iter()).for_each_with(server_key, |server_key, (x, y)| x.xor_state(y, server_key));
    }
}



#[cfg(test)]

mod tests {

    use super::*;
    use std::time::Instant;
    use tfhe::boolean::gen_keys;
    use base::primitive::*;

    #[test]
    fn test_ctr() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);


        let curr_key = Key::from_u128_enc(0x2b7e1516_28aed2a6a_bf71588_09cf4f3c , &client_key);
        let keys = curr_key.generate_round_keys(&server_key);
        let counters = vec![State::from_u128_enc(0x3243f6a8_885a308d_00000000_00000000, &client_key), State::from_u128_enc(0x3243f6a8_885a308d_00000000_00000001, &client_key)];
        let ctr = CTR::new(&keys, &counters, 2);

        let plaintext_block_0 = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0370734, &client_key); 
        let plaintext_block_1 = State::from_u128_enc(0x3243f6a8_885a308d_313198a2_e0372324, &client_key); 
        let mut plaintext = vec![plaintext_block_0, plaintext_block_1];


        let start = Instant::now();
        with_server_key(|server_key| {
            ctr.encrypt(&mut plaintext, &server_key);  
        });
        println!("ENCRYPT TIME TAKEN {:?}", start.elapsed());

        let start = Instant::now();
        with_server_key(|server_key| {
            ctr.decrypt(&mut plaintext, &server_key);
        });
        println!("DECRYPT TIME TAKEN {:?}", start.elapsed());
        
        assert_eq!(plaintext[0].decrypt_to_u128(&client_key), 0x3243f6a8_885a308d_313198a2_e0370734);
        assert_eq!(plaintext[1].decrypt_to_u128(&client_key), 0x3243f6a8_885a308d_313198a2_e0372324);

    }
}