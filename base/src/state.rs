use std::collections::VecDeque;
use rayon::prelude::*;

use crate::primitive::*;

struct TransposedState {
    data: [FHEByte; 16]
    // Each element of this array is the following in the original (not transposed) state matrix
    // 0 4 8 12
    // 1 5 9 13
    // 2 6 10 14
    // 3 7 11 15 
}

impl TransposedState {
    fn sub_bytes(&mut self) {
        self.data = self
            .data
            .par_iter()
            .map(|byte| byte.sub_byte())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    fn mix_columns(&mut self) {

        with_thread_pool(|pool| {
            let mut y_0: Vec<_> = self.data[8..12].par_iter().zip(self.data[12..16].par_iter()).map(|(x, y)| x.xor(y, pool)).collect(); // 2 xor 3
            let mut y_1: Vec<_> = y_0.clone(); // 2 xor 3
            let mut y_2: Vec<_> = self.data[..4].par_iter().zip(self.data[4..8].par_iter()).map(|(x, y)| x.xor(y, pool)).collect(); // 0 xor 1
            let mut y_3 = y_2.clone(); // 0 xor 1

            y_0.par_iter_mut().zip(self.data[4..8].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_1.par_iter_mut().zip(self.data[..4].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_2.par_iter_mut().zip(self.data[12..].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_3.par_iter_mut().zip(self.data[8..12].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));

            self.data.par_iter_mut().for_each(|x| x.mul_x_gf2_in_place(pool));

            y_0.par_iter_mut().zip(self.data[..4].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_1.par_iter_mut().zip(self.data[4..8].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_2.par_iter_mut().zip(self.data[8..12].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_3.par_iter_mut().zip(self.data[12..].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));

            y_0.par_iter_mut().zip(self.data[4..8].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_1.par_iter_mut().zip(self.data[8..12].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_2.par_iter_mut().zip(self.data[12..].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
            y_3.par_iter_mut().zip(self.data[..4].par_iter()).for_each(|(x, y)| x.xor_in_place(y, pool));
        })
    }

    fn xor_key_enc(&mut self, key: [FHEByte; 16]) {

    }

    fn shift_cols(&mut self) {
        let slice = &mut self.data[..4];
        slice.rotate_left(1);
        let slice = &mut self.data[4..8];
        slice.rotate_left(2);
        let slice = &mut self.data[8..12];
        slice.rotate_left(3);
    }
}
