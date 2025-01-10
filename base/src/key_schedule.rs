use std::time::Instant;

use rayon::prelude::*;
use tfhe::boolean::prelude::*;

use crate::primitive::*;


#[derive(Clone)]
pub struct Key {
    pub data: [FHEByte; 16]
}


impl Key {

    pub fn from_u128_enc(value: u128, client_key: &ClientKey) -> Self {
        let data: [FHEByte; 16] = (0..16)
        .rev()
        .map(|i| FHEByte::from_u8_enc(&{ ((value >> 8 * i) & 0xFF) as u8 }, client_key))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

        Self { data }
    }

    pub fn from_u128_clear(value: u128, server_key: &ServerKey) -> Self {
        let data: [FHEByte; 16] = (0..16)
        .rev()
        .map(|i| FHEByte::from_u8_clear(&{ ((value >> 8 * i) & 0xFF) as u8 }, server_key))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

        Self { data }
    }


    pub fn from_u8_enc(data: &[u8; 16], client_key: &ClientKey) -> Self {
        let data = data.map(|value| FHEByte::from_u8_enc(&value, client_key));
        Self { data }
    }

    pub fn from_u8_clear(data: &[u8; 16], server_key: &ServerKey) -> Self {
        let data = data.map(|value| FHEByte::from_u8_clear(&value, server_key));
        Self { data }
    }

    pub fn generate_next_key_in_place(&mut self, rcon: &u8, server_key: &ServerKey) {

        // let temp = [self.data[7].sub_byte(server_key).xor(&FHEByte::from_u8_clear(rcon, server_key), server_key), self.data[11].sub_byte(server_key), self.data[15].sub_byte(server_key), self.data[3].sub_byte(server_key)];
        
        let mut temp: Vec<_> = [7, 11, 15, 3].into_par_iter().map(|i| self.data[i].sub_byte(server_key)).collect();
        temp[0].xor_in_place(&FHEByte::from_u8_clear(rcon, server_key), server_key);

        let start = Instant::now();
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

        println!("{:?}", start.elapsed());
    }

    pub fn decrypt_to_u8(&self, client_key: &ClientKey) -> [u8; 16] {
        self.data.iter().map(|x| (&x.decrypt(client_key))                .iter()
        .enumerate()
        .filter_map(|(i, &x)| x.then(|| 2_u8.pow(8 - (i + 1) as u32)))
        .sum()).collect::<Vec<_>>().try_into().unwrap()
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
        let state = Key::from_u128_enc(0x2b28ab09_7eaef7cf_15d2154f_16a6883c , &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        let start = Instant::now();
        with_server_key(|server_key| {
            test_data
                .par_iter_mut()
                .for_each_with(server_key, |server_key, state| {
                    state.generate_next_key_in_place(&0x01, &server_key)
                })
        });

        println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
        println!("TIME TAKEN {:?}", start.elapsed() / 1);

    }
}