use crate::primitive::*;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;

#[derive(Clone)]
struct State {
    data: [FHEByte; 16], // Each element of this array is the following in the transposed state matrix
                         // 0 4 8 12
                         // 1 5 9 13
                         // 2 6 10 14
                         // 3 7 11 15
}

impl State {
    fn new(value: u128, client_key: &ClientKey) -> Self {
        let data: [FHEByte; 16] = (0..16)
            .rev()
            .map(|i| FHEByte::from_u8(&{ ((value >> 8 * i) & 0xFF) as u8 }, client_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        State { data }
    }
    fn sub_bytes(&mut self, server_key: &ServerKey) {
        self.data = self
            .data
            .par_iter()
            .map_with(server_key, |server_key, byte| byte.sub_byte(server_key))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    fn mix_columns(&mut self, server_key: &ServerKey) {
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

    fn xor_key_enc(&mut self, key: [FHEByte; 16], server_key: &ServerKey) {

    }

    fn decrypt_to_u8(&self, client_key: &ClientKey) -> [u8; 16] {
        self.data.iter().map(|x| (&x.decrypt(client_key))                .iter()
        .enumerate()
        .filter_map(|(i, &x)| x.then(|| 2_u8.pow(8 - (i + 1) as u32)))
        .sum()).collect::<Vec<_>>().try_into().unwrap()
    }

    fn shift_rows(&mut self) {
        let slice = &mut self.data[..4];
        slice.rotate_left(1);
        let slice = &mut self.data[4..8];
        slice.rotate_left(2);
        let slice = &mut self.data[8..12];
        slice.rotate_left(3);
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
}