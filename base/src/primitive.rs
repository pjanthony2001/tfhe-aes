use dashmap::DashMap;
use rayon::prelude::*;
use std::cell::RefCell;
use std::sync::Arc;

use std::collections::VecDeque;
use std::sync::{RwLock, LazyLock};
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::*;

use crate::boolean_tree::BooleanExpr;
use crate::sbox::*;


    pub static INTERNAL_KEY: RwLock<Option<ServerKey>> = const { RwLock::new(None) };
    pub static S_BOX_EXPR: RwLock<LazyLock<Vec<BooleanExpr>>> = RwLock::new(LazyLock::new(||generate_reduced_bool_expr(S_BOX_DATA)));
    pub static INV_S_BOX_EXPR: RwLock<LazyLock<Vec<BooleanExpr>>> = RwLock::new(LazyLock::new(||generate_reduced_bool_expr(INV_S_BOX_DATA)));

pub fn set_server_key(key: &ServerKey) {
    let mut guard_internal_key = INTERNAL_KEY.write().unwrap();
    *guard_internal_key = Some(key.clone());
}

pub fn unset_server_key() {
    let mut guard_internal_key = INTERNAL_KEY.write().unwrap();
    *guard_internal_key = None;
}

#[inline(always)]
pub fn with_server_key<F, T>(func: F) -> T
where
    F: FnOnce(&ServerKey) -> T + std::marker::Send,
    T: std::marker::Send,
{

    let guard_internal_key = INTERNAL_KEY.read().unwrap();
    let server_key = &guard_internal_key.as_ref().expect("Set the server key before calling any functions !!");
    func(server_key)

}

#[derive(Clone, Debug)]
pub struct FHEByte {
    // TODO: BIG ENDIAN instead of little endian
    data: VecDeque<Ciphertext>, //TODO: Convert to fixed size array
}

impl FHEByte {
    pub fn new(bool_data: &[bool], client_key: &ClientKey) -> Self {
        assert!(
            bool_data.len() == 8,
            "FHEByte has to be initialized with * booleans !"
        );
        let data = bool_data
            .into_iter()
            .map(|x| client_key.encrypt(*x).into())
            .collect();
        Self { data }
    }

    pub fn from_u8_enc(value: &u8, client_key: &ClientKey) -> Self {
        let data: VecDeque<Ciphertext> = (0..8)
            .rev()
            .map(|i| client_key.encrypt(value & (1 << i) != 0))
            .collect();
        Self { data }
    }

    pub fn from_u8_clear(value: &u8, server_key: &ServerKey) -> Self {
        let data: VecDeque<Ciphertext> = (0..8)
            .rev()
            .map(|i| server_key.trivial_encrypt(value & (1 << i) != 0))
            .collect();
        Self { data }
    }

    pub fn decrypt(&self, client_key: &ClientKey) -> Vec<bool> {
        self.data.iter().map(|x| client_key.decrypt(x)).collect()
    }

    pub fn decrypt_to_u8(&self, client_key: &ClientKey) -> u8 {
        self.decrypt(client_key)
        .iter()
        .enumerate()
        .filter_map(|(i, &x)| x.then(|| 2_u8.pow(8 - (i + 1) as u32)))
        .sum()
    }

    pub fn xor_in_place(&mut self, rhs: &Self, server_key: &ServerKey) {
        self.data
            .par_iter_mut()
            .zip(rhs.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| server_key.xor_assign(x, y))
    }

    pub fn xor(&self, rhs: &Self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.xor_in_place(rhs, server_key);
        result
    }

    pub fn and_in_place(&mut self, rhs: &Self, server_key: &ServerKey) {
        self.data
            .par_iter_mut()
            .zip(rhs.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| server_key.and_assign(x, y))
    }

    pub fn and(&self, rhs: &Self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.and_in_place(rhs, server_key);
        result
    }

    pub fn or_in_place(&mut self, rhs: &Self, server_key: &ServerKey) {
        self.data
            .par_iter_mut()
            .zip(rhs.data.par_iter())
            .for_each_with(server_key, |server_key, (x, y)| server_key.or_assign(x, y))
    }

    pub fn or(&self, rhs: &Self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.or_in_place(rhs, server_key);
        result
    }

    pub fn not_in_place(&mut self, server_key: &ServerKey) {
        self.data
            .par_iter_mut()
            .for_each_with(server_key, |server_key, x| server_key.not_assign(x))
    }

    pub fn not(&self, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.not_in_place(server_key);
        result
    }

    fn rotate_right_in_place(&mut self, shift: usize) -> () {
        //TODO: Convert to fixed size array
        self.data.rotate_right(shift);
    }

    fn rotate_left_in_place(&mut self, shift: usize) -> () {
        //TODO: Convert to fixed size array
        self.data.rotate_left(shift);
    }

    fn rotate_left(&self, shift: usize) -> Self {
        let mut result = self.clone();
        result.rotate_left_in_place(shift);
        result
    }

    fn rotate_right(&self, shift: usize) -> Self {
        let mut result = self.clone();
        result.rotate_right_in_place(shift);
        result
    }

    fn shift_right_in_place(&mut self, shift: usize, server_key: &ServerKey) -> () {
        //TODO: Convert to fixed size array
        let shift = shift.clamp(0, 8);
        for _ in 0..shift {
            self.data.push_front(server_key.trivial_encrypt(false));
            self.data.pop_back();
        }
    }

    fn shift_left_in_place(&mut self, shift: usize, server_key: &ServerKey) -> () {
        //TODO: Convert to fixed size array
        let shift = shift.clamp(0, 8);

        for _ in 0..shift {
            self.data.push_back(server_key.trivial_encrypt(false));
            self.data.pop_front();
        }
    }

    fn shift_left(&self, shift: usize, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.shift_left_in_place(shift, server_key);
        result
    }

    fn shift_right(&self, shift: usize, server_key: &ServerKey) -> Self {
        let mut result = self.clone();
        result.shift_right_in_place(shift, server_key);
        result
    }

    pub fn trivial_clear(clear_value: u8, server_key: &ServerKey) -> Self {
        let data = (0..8)
            .rev()
            .into_iter()
            .map(|shift| server_key.trivial_encrypt(clear_value & (1 << shift) != 0))
            .collect();
        FHEByte { data }
    }

    pub fn trivial_false(server_key: &ServerKey) -> Self {
        Self::trivial_clear(0, server_key)
    }

    fn _sub_byte(&self) -> Self {
        //TODO: After staged execution, this should be removed. Old iterator version.
        let visited = Arc::new(DashMap::new());

        
    let lazy_lock_sbox = S_BOX_EXPR.read().unwrap();
    let s_box_exprs: &Vec<BooleanExpr> = lazy_lock_sbox.as_ref();


        let data = 
            s_box_exprs
                .iter()
                .rev()
                .map(move |x| {
                    let mut curr_data = self.data.clone();
                    let curr_visited = visited.clone();
                    let guard_maybe_key = INTERNAL_KEY.read().unwrap();
                    let server_key = guard_maybe_key.as_ref().expect("INIT BEFORE USING KEY");
                        x.evaluate(
                            curr_data.make_contiguous(),
                            server_key,
                            curr_visited,
                        )
                    })
                .collect();

        FHEByte { data }
    }

    pub fn sub_byte(&self, server_key: &ServerKey) -> Self {
        //TODO: Do staged evaluation.
        let visited = Arc::new(DashMap::new());
        let curr_data = self.data.iter().rev().cloned().collect::<Vec<_>>();

        let lazy_lock_sbox = S_BOX_EXPR.read().unwrap();
        let s_box_exprs: &Vec<BooleanExpr> = lazy_lock_sbox.as_ref();


        let data =
            s_box_exprs
                .par_iter()
                .map_with(
                    (curr_data, server_key),
                    move |(curr_data, server_key), x| {
                        x.evaluate(
                            curr_data,
                            server_key,
                            Arc::clone(&visited),
                        )
                    },
                )
                .collect();

        FHEByte { data }
    }

    pub fn inv_sub_byte(&self, server_key: &ServerKey) -> Self {
        //TODO: Do staged evaluation.
        let visited = Arc::new(DashMap::new());
        let curr_data = self.data.iter().rev().cloned().collect::<Vec<_>>();

        let lazy_lock_inv_sbox = INV_S_BOX_EXPR.read().unwrap();
        let inv_s_box_exprs: &Vec<BooleanExpr> = lazy_lock_inv_sbox.as_ref();


        let data =
        inv_s_box_exprs
                .par_iter()
                .map_with(
                    (curr_data, server_key),
                    move |(curr_data, server_key), x| {
                        x.evaluate(
                            curr_data,
                            server_key,
                            Arc::clone(&visited),
                        )
                    },
                )
                .collect();

        FHEByte { data }
    }

    pub fn mul_x_gf2_in_place(&mut self, server_key: &ServerKey) {
        let conditional_bit = self.data[0].clone();
        self.shift_left_in_place(1, server_key);
        let irr_poly = FHEByte::trivial_clear(0x1b, server_key);

        self.data = self
            .data
            .par_iter()
            .zip(irr_poly.data.par_iter())
            .map_with(server_key, |server_key, (x, y)| {
                server_key.mux(&conditional_bit, &server_key.xor(x, y), x)
            })
            .collect();
    }

    pub fn mul_x_gf2(&self, server_key: &ServerKey) -> Self {
        //TODO: Convert xor to in place versions, using assign and replace the xor, add clear version
        let mut result = self.clone();
        result.mul_x_gf2_in_place(server_key);
        result
    }
}

#[cfg(test)]

mod tests {
    use std::time::Instant;

    use super::*;
    use tfhe::boolean::gen_keys;

    #[test]
    fn test_xor() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut test_data: Vec<_> = (0..200).into_iter().map(|_| x.clone()).collect();
        let start = Instant::now();
        with_server_key(|server_key| {
            test_data
                .par_iter_mut()
                .for_each_with(server_key, |server_key, x| x.xor_in_place(&y, server_key))
        });

        println!("PAR_ITER_XOR_METHOD {:?}", start.elapsed() / 200);
        assert!(
            test_data[0].decrypt(&client_key)
                == vec![false, true, false, true, false, false, false, false]
        );
    }

    #[test]
    fn test_and() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );

        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut test_data: Vec<_> = (0..200).into_iter().map(|_| x.clone()).collect();
        let start = Instant::now();
        with_server_key(|server_key| {
            test_data
                .par_iter_mut()
                .for_each_with(server_key, |server_key, x| x.and_in_place(&y, server_key))
        });

        println!("PAR_ITER_AND_METHOD {:?}", start.elapsed() / 1000);

        assert!(
            test_data[0].decrypt(&client_key)
                == vec![true, false, true, false, true, true, true, true]
        );
    }

    #[test]
    fn test_sub_byte() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);

        let x = FHEByte::from_u8_enc(&0x01, &client_key);

        let start = Instant::now();

        let y: Vec<_> = with_server_key(|server_key| {
            (0..1)
                .into_par_iter()
                .map_with(server_key, |server_key, _| x.sub_byte(server_key))
                .collect()
        });

        println!("CONSUME_PARALLEL_ {:?}", start.elapsed() / 1);

        assert_eq!(y[0].decrypt_to_u8(&client_key), 0x7c, "{:#x?}", y[0].decrypt_to_u8(&client_key));
    }

    fn clear_mul_x_gf2(x: &u8) -> u8 {
        let mut res = x.clone();
        res <<= 1;
        if x & 0x80 != 0 {
            res ^= 0x1b;
        } 

        res
    }
    #[test]
    fn test_mul_gf_2() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);

        for clear_value in 0..=255 {
            let x = FHEByte::from_u8_enc(&clear_value, &client_key);
            let start = Instant::now();
    
            let y: Vec<_> = with_server_key(|server_key| {
                (0..1)
                    .into_par_iter()
                    .map_with(server_key, |server_key, _| x.mul_x_gf2(server_key))
                    .collect()
            });
    
            println!("CONSUME_PARALLEL_ {:?}", start.elapsed() / 1);
    
            assert_eq!(y[0].decrypt_to_u8(&client_key), clear_mul_x_gf2(&clear_value))
        }
    }
}
