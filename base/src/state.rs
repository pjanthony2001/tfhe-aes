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
