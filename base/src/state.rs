use std::collections::VecDeque;

use crate::primitive::*;

struct State {
    columns: VecDeque<VecDeque<FHEByte>>,
}

impl State {
    fn sub_bytes(&mut self) {
        self.columns = self
            .columns
            .iter()
            .map(|col| col.into_iter().map(|byte| byte.sub_byte()).collect())
            .collect();
    }

    fn mix_columns(&mut self) {}

    fn xor_key(&mut self, key: Self) {}

    fn shift_cols(&mut self) {}
}
