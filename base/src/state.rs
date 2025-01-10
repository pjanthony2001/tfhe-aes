use crate::primitive::*;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;
use crate::Key;

#[derive(Clone)]
pub struct State {
    data: [FHEByte; 16], // Each element of this array is the following in the transposed state matrix
                         // 0 4 8 12
                         // 1 5 9 13
                         // 2 6 10 14
                         // 3 7 11 15
}

impl State {
    pub fn new(value: u128, client_key: &ClientKey) -> Self {
        let data: [FHEByte; 16] = (0..16)
            .rev()
            .map(|i| FHEByte::from_u8_enc(&{ ((value >> 8 * i) & 0xFF) as u8 }, client_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        State { data }
    }

    pub fn sub_bytes(&mut self, server_key: &ServerKey) {
        self.data = self
            .data
            .par_iter()
            .map_with(server_key, |server_key, byte| byte.sub_byte(server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    pub fn inv_sub_bytes(&mut self, server_key: &ServerKey) {
        self.data = self
            .data
            .par_iter()
            .map_with(server_key, |server_key, byte| byte.inv_sub_byte(server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    pub fn mix_columns(&mut self, server_key: &ServerKey) {
        //pass along the server_key !
        let data_order: [usize; 16] = [8, 9, 10, 11, 8, 9 , 10, 11, 0, 1, 2, 3, 0, 1, 2, 3];

        let mut y: [FHEByte; 16] = data_order
            .into_par_iter()
            .map_with(server_key, |server_key, i| {
                self.data[i].xor(&self.data[4 + i], server_key)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let data_chained = self.data[4..8]
            .par_iter()
            .chain(self.data[..4].par_iter())
            .chain(self.data[12..].par_iter())
            .chain(self.data[8..12].par_iter());
        y.par_iter_mut()
            .zip(data_chained)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        

        self.data
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| x.mul_x_gf2_in_place(server_key));

        y.par_iter_mut()
            .zip(self.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        let data_chained = self.data[4..8]
            .par_iter()
            .chain(self.data[8..12].par_iter())
            .chain(self.data[12..].par_iter())
            .chain(self.data[..4].par_iter());

        y.par_iter_mut()
            .zip(data_chained)
            .for_each_with(server_key, |server_key, (x, y)| {
                x.xor_in_place(y, server_key)
            });

        self.data = y
    }


    pub fn inv_mix_columns(&mut self, server_key: &ServerKey) { // TEST THOROUGHLY !!

        let mut y: [FHEByte; 16] = (0..16_usize)
            .into_par_iter()
            .map_with(server_key, |server_key, i| {
                self.data[i].xor(&self.data[(i + 4) % 16], server_key)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // y_i = (x_i ^ x_(i + 1) % 4)

        let mut temp_0: [FHEByte; 8] = (0..8)
        .into_par_iter()            
        .map_with(server_key, |server_key, i| {
            self.data[i].xor(&self.data[i + 8], server_key)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // (X_i XOR X_(i + 2))

        temp_0.par_iter_mut().for_each_with(server_key, |server_key, x| {
            x.mul_x_gf2_in_place(server_key)
        }); // 02 * (X_i XOR X_(i + 2))

        temp_0.par_iter_mut().for_each_with(server_key, |server_key, x| {
            x.mul_x_gf2_in_place(server_key)
        }); // 04 * (X_i XOR X_(i + 2))

        let mut temp_1: [FHEByte; 4] = y[..4].par_iter().zip(y[8..12].par_iter())     
        .map_with(server_key, |server_key, (x, y)| {
            x.xor(y, server_key)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // (X_0 ^ X_1 ^ X_2 ^ X_3)

        let temp_0_iter = temp_0[..4].par_iter().chain(temp_0[4..].par_iter()).chain(temp_0[..4].par_iter()).chain(temp_0[4..].par_iter());
        
        y.par_iter_mut().for_each_with(server_key, |server_key, x| {
            x.mul_x_gf2_in_place(server_key)
        });

        y.par_iter_mut().zip(temp_0_iter).for_each_with(server_key, |server_key, (x, y)| {
            x.xor_in_place(y, server_key)
        });

        let temp_1_iter = temp_1.par_iter().chain(temp_1.par_iter()).chain(temp_1.par_iter()).chain(temp_1.par_iter());

        self.data.par_iter_mut().zip(y.par_iter()).for_each_with(server_key, |server_key, (x, y)| {
            x.xor_in_place(y, server_key)
        });

        self.data.par_iter_mut().zip(temp_1_iter).for_each_with(server_key, |server_key, (x, y)| {
            x.xor_in_place(y, server_key)
        }); 

        temp_1.par_iter_mut().for_each_with(server_key, |server_key, x| {
            x.mul_x_gf2_in_place(server_key)
        });

        temp_1.par_iter_mut().for_each_with(server_key, |server_key, x| {
            x.mul_x_gf2_in_place(server_key)
        });

        temp_1.par_iter_mut().for_each_with(server_key, |server_key, x| {
            x.mul_x_gf2_in_place(server_key)
        }); //08 * (X_0 ^ X_1 ^ X_2 ^ X_3)

        let temp_1_iter = temp_1.par_iter().chain(temp_1.par_iter()).chain(temp_1.par_iter()).chain(temp_1.par_iter());

        self.data.par_iter_mut().zip(temp_1_iter).for_each_with(server_key, |server_key, (x, y)| {
            x.xor_in_place(y, server_key)
        }); 

    }

    pub fn xor_key_enc(&mut self, key: &Key, server_key: &ServerKey) {
        self.data.par_iter_mut()
        .zip(key.data.par_iter())
        .for_each_with(server_key, |server_key, (x, y)| {
            x.xor_in_place(y, server_key)
        });
    }

    pub fn xor_key_clear(&mut self, key: &[u8; 16], server_key: &ServerKey) {
        self.data.par_iter_mut()
        .zip(key.into_par_iter())
        .for_each_with(server_key, |server_key, (x, y)| {
            x.xor_in_place(&FHEByte::trivial_clear(*y, server_key), server_key)
        });
    }

    pub fn decrypt_to_u8(&self, client_key: &ClientKey) -> [u8; 16] {
        self.data.iter().map(|x| (&x.decrypt(client_key))                .iter()
        .enumerate()
        .filter_map(|(i, &x)| x.then(|| 2_u8.pow(8 - (i + 1) as u32)))
        .sum()).collect::<Vec<_>>().try_into().unwrap()
    }

    pub fn decrypt_to_u128(&self, client_key: &ClientKey) -> u128 {
        let u8_data = self.decrypt_to_u8(client_key);
        println!("{:#x?}", u8_data);
        let mut res: u128 = 0;
        for i in 0..15 {
            res ^= u8_data[i] as u128;
            res <<= 8;
            println!("{:#x?}", res);
        }

        res ^= u8_data[15] as u128;
        res

    }

    pub fn shift_rows(&mut self) {
        let mut slice = &mut self.data[4..8];
        slice.rotate_left(1);
        slice = &mut self.data[8..12];
        slice.rotate_left(2);
        slice = &mut self.data[12..];
        slice.rotate_left(3);
    }

    pub fn inv_shift_rows(&mut self) {
        let mut slice = &mut self.data[4..8];
        slice.rotate_right(1);
        slice = &mut self.data[8..12];
        slice.rotate_right(2);
        slice = &mut self.data[12..];
        slice.rotate_right(3);
    }


}

#[cfg(test)]

mod tests {
    use std::time::Instant;

    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_mix_columns() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        let state = State::new(0xd4e0b81e_bfb44127_5d521198_30aef1e5 , &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

        let start = Instant::now();
        with_server_key(|server_key| {
            test_data
                .par_iter_mut()
                .for_each_with(server_key, |server_key, state| {
                    state.mix_columns(&server_key)
                })
        });

        println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
        println!("TIME TAKEN {:?}", start.elapsed() / 1);

    }

#[test]
fn test_sub_bytes() {
    let (client_key, server_key) = gen_keys();
    set_server_key(&server_key);
    let state = State::new(0x19a09ae9_3df4c6f8_e3e28d48_be2b2a08, &client_key);
    let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

    let start = Instant::now();
    with_server_key(|server_key| {
        test_data
            .par_iter_mut()
            .map_with(server_key, |server_key, state| {
                state.sub_bytes(&server_key)
            })
            .collect::<Vec<_>>()
    });

    println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
    println!("TIME TAKEN {:?}", start.elapsed() / 1);

    }
    #[test]
fn test_shift_rows() {
    let (client_key, server_key) = gen_keys();
    set_server_key(&server_key);
    let state = State::new(0x19a09ae9_3df4c6f8_e3e28d48_be2b2a08, &client_key);
    let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();

    let start = Instant::now();
    with_server_key(|server_key| {
        test_data
            .par_iter_mut()
            .map_with(server_key, |server_key, state| {
                state.shift_rows()
            })
            .collect::<Vec<_>>()
    });

    println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
    println!("TIME TAKEN {:?}", start.elapsed() / 1);

    }

    #[test]
    fn test_inv_shift_rows() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        let state = State::new(0xd4e0b81e_bfb44127_5d521198_30aef1e5, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();
    
        let start = Instant::now();
        with_server_key(|server_key| {
            test_data
                .par_iter_mut()
                .map_with(server_key, |server_key, state| {
                    state.inv_shift_rows()
                })
                .collect::<Vec<_>>()
        });
    
        println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
        println!("TIME TAKEN {:?}", start.elapsed() / 1);
    
        }

    #[test]
    fn test_inv_mix_columns() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        let state = State::new(0x04e04828_66cbf806_8119d326_e59a7a4c, &client_key);
        let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();
    
        let start = Instant::now();
        with_server_key(|server_key| {
            test_data
                .par_iter_mut()
                .map_with(server_key, |server_key, state| {
                    state.inv_mix_columns(&server_key)
                })
                .collect::<Vec<_>>()
        });
    
        println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
        println!("TIME TAKEN {:?}", start.elapsed() / 1);
    
        }

        #[test]
        fn test_key_schedule() {
            let (client_key, server_key) = gen_keys();
            set_server_key(&server_key);
            let state = State::new(0x04e04828_66cbf806_8119d326_e59a7a4c, &client_key);
            let mut test_data: Vec<_> = (0..1).into_iter().map(|_| state.clone()).collect();
        
            let start = Instant::now();
            with_server_key(|server_key| {
                test_data
                    .par_iter_mut()
                    .map_with(server_key, |server_key, state| {
                        state.xor_key_enc(&Key::from_u128_enc(0x01, &client_key), &server_key)
                    })
                    .collect::<Vec<_>>()
            });
        
            println!("{:#x?}", test_data[0].decrypt_to_u8(&client_key));
            println!("TIME TAKEN {:?}", start.elapsed() / 1);
        
            }

        #[test]
        fn test_decrypt_u128() {
            let (client_key, server_key) = gen_keys();
            set_server_key(&server_key);
            let state = State::new(0x04e04828_66cbf806_8119d326_e59a7a4c, &client_key);
            
            assert_eq!(state.decrypt_to_u128(&client_key), 0x04e04828_66cbf806_8119d326_e59a7a4c, "{:#x?}", state.decrypt_to_u128(&client_key));
        
        }





}