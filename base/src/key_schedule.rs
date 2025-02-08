use std::time::Instant;

use rayon::prelude::*;
use tfhe::boolean::prelude::*;

use crate::primitive::*;

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

#[derive(Clone, Debug)]
pub struct Key {
    pub data: [FHEByte; 16]
}

impl Key {

    pub fn from_u128_enc(value: u128, client_key: &ClientKey) -> Self {
        let mut data: [FHEByte; 16] = (0..16)
        .rev()
        .map(|i| FHEByte::from_u8_enc(&{ ((value >> 8 * i) & 0xFF) as u8 }, client_key))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();


        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);

        Self { data }
    }

    pub fn from_u128_clear(value: u128, server_key: &ServerKey) -> Self {
        let mut data: [FHEByte; 16] = (0..16)
        .rev()
        .map(|i| FHEByte::from_u8_clear(&{ ((value >> 8 * i) & 0xFF) as u8 }, server_key))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);

        Self { data }
    }


    pub fn from_u8_enc(data: &[u8; 16], client_key: &ClientKey) -> Self {
        let mut data = data.map(|value| FHEByte::from_u8_enc(&value, client_key));
        
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);
        Self { data }
    }

    pub fn from_u8_clear(data: &[u8; 16], server_key: &ServerKey) -> Self {
        let mut data = data.map(|value| FHEByte::from_u8_clear(&value, server_key));
        
        data.swap(1, 4);
        data.swap(2, 8);
        data.swap(3, 12);

        data.swap(6, 9);
        data.swap(7, 13);

        data.swap(11, 14);
        Self { data }
    }

    pub fn generate_next_key_in_place(&mut self, rcon: &u8, server_key: &ServerKey) {


        
        let mut temp: Vec<_> = [7, 11, 15, 3].into_par_iter().map(|i| self.data[i].sub_byte(server_key)).collect();
        temp[0].xor_in_place(&FHEByte::from_u8_clear(rcon, server_key), server_key);

        self.data
        .par_iter_mut()
        .enumerate()
        .filter(|(i, _)| i % 4 == 0)
        .for_each_with(server_key, |server_key, (i, x)| {
            x.xor_in_place(&temp[i / 4], server_key)
        });


        self.data
        .par_chunks_mut(2)
        .enumerate()
        .filter(|(i, _)| i % 2 == 0)
        .for_each_with(server_key, |server_key, (i, x)| {
            let (a, b) = x.split_at_mut(1);
            b[0].xor_in_place(&a[0], server_key)
        });

        self.data[1..]
        .par_chunks_mut(2)
        .enumerate()
        .filter(|(i, _)| i % 2 == 0)
        .for_each_with(server_key, |server_key, (i, x)| {
            let (a, b) = x.split_at_mut(1);
            b[0].xor_in_place(&a[0], server_key)
        });

        self.data
        .par_chunks_mut(2)
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .for_each_with(server_key, |server_key, (i, x)| {
            let (a, b) = x.split_at_mut(1);
            b[0].xor_in_place(&a[0], server_key)
        });
        

    }

    pub fn decrypt_to_u8(&self, client_key: &ClientKey) -> [u8; 16] {
        let mut decrypted_data: [u8; 16] = self.data.iter().map(|x| (&x.decrypt(client_key))
        .iter()
        .enumerate()
        .filter_map(|(i, &x)| x.then(|| 2_u8.pow(8 - (i + 1) as u32)))
        .sum()).collect::<Vec<_>>().try_into().unwrap();

        decrypted_data.swap(1, 4);
        decrypted_data.swap(2, 8);
        decrypted_data.swap(3, 12);

        decrypted_data.swap(6, 9);
        decrypted_data.swap(7, 13);

        decrypted_data.swap(11, 14);

        decrypted_data
    }

    pub fn generate_round_keys(&self, server_key: &ServerKey) -> [Key; 11] {
        let mut keys = vec![self.clone()];
        for i in 0..10 {
            let mut key = keys[i].clone();
            key.generate_next_key_in_place(&RCON[i], &server_key);
            keys.push(key);
        }


        keys.try_into().expect("There should be 11 Keys")
    }
}


#[cfg(test)]

mod tests {
    use std::time::Instant;

    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_key_schedule() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        let key = Key::from_u128_enc(0x2b7e151628aed2a6abf7158809cf4f3c  , &client_key);

        let start = Instant::now();
        with_server_key(|server_key| {
            let keys = key.generate_round_keys(server_key);
            for key in keys.iter() {
                println!("{:#x?}", key.decrypt_to_u8(&client_key));
            }
        });

        println!("TIME TAKEN {:?}", start.elapsed() / 1);

    }
}