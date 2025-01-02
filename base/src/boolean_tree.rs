use ::std::rc::Rc;
use dashmap::DashMap;
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::ops::Not;
use std::sync::Arc;
use tfhe::boolean::prelude::*;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Operand {
    True,
    False,
    Bit0,
    NotBit0,
    Bit1,
    NotBit1,
    Bit2,
    NotBit2,
    Bit3,
    NotBit3,
    Bit4,
    NotBit4,
    Bit5,
    NotBit5,
    Bit6,
    NotBit6,
    Bit7,
    NotBit7,
}

impl Not for Operand {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Operand::True => Operand::False,
            Operand::False => Operand::True,
            Operand::Bit0 => Operand::NotBit0,
            Operand::NotBit0 => Operand::Bit0,
            Operand::Bit1 => Operand::NotBit1,
            Operand::NotBit1 => Operand::Bit1,
            Operand::Bit2 => Operand::NotBit2,
            Operand::NotBit2 => Operand::Bit2,
            Operand::Bit3 => Operand::NotBit3,
            Operand::NotBit3 => Operand::Bit3,
            Operand::Bit4 => Operand::NotBit4,
            Operand::NotBit4 => Operand::Bit4,
            Operand::Bit5 => Operand::NotBit5,
            Operand::NotBit5 => Operand::Bit5,
            Operand::Bit6 => Operand::NotBit6,
            Operand::NotBit6 => Operand::Bit6,
            Operand::Bit7 => Operand::NotBit7,
            Operand::NotBit7 => Operand::Bit7,
        }
    }
}

impl From<bool> for Operand {
    fn from(value: bool) -> Self {
        match value {
            true => Operand::True,
            false => Operand::False,
        }
    }
}

impl Operand {
    fn evaluate(
        &self,
        bits: &[Ciphertext],
        true_enc: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match self {
            Operand::True => true_enc.clone(),
            Operand::False => server_key.not(true_enc),
            Operand::Bit0 => bits[0].clone(),
            Operand::NotBit0 => server_key.not(&bits[0]),
            Operand::Bit1 => bits[1].clone(),
            Operand::NotBit1 => server_key.not(&bits[1]),
            Operand::Bit2 => bits[2].clone(),
            Operand::NotBit2 => server_key.not(&bits[2]),
            Operand::Bit3 => bits[3].clone(),
            Operand::NotBit3 => server_key.not(&bits[3]),
            Operand::Bit4 => bits[4].clone(),
            Operand::NotBit4 => server_key.not(&bits[4]),
            Operand::Bit5 => bits[5].clone(),
            Operand::NotBit5 => server_key.not(&bits[5]),
            Operand::Bit6 => bits[6].clone(),
            Operand::NotBit6 => server_key.not(&bits[6]),
            Operand::Bit7 => bits[7].clone(),
            Operand::NotBit7 => server_key.not(&bits[7]),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BooleanExpr {
    Operand(Operand),
    And(Box<BooleanExpr>, Box<BooleanExpr>),
    Or(Box<BooleanExpr>, Box<BooleanExpr>),
    Xor(Box<BooleanExpr>, Box<BooleanExpr>),
    Mux(Operand, Box<BooleanExpr>, Box<BooleanExpr>),
}
impl BooleanExpr {
    fn eq_commutative(
        inner_0: &Self,
        inner_1: &Self,
        other_inner_0: &Self,
        other_inner_1: &Self,
    ) -> bool {
        (inner_0 == other_inner_0 && inner_1 == other_inner_1)
            || (inner_0 == other_inner_1 && inner_1 == other_inner_0)
    }
}

impl Not for BooleanExpr {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            BooleanExpr::Operand(inner) => BooleanExpr::Operand(!inner),
            BooleanExpr::And(inner_0, inner_1) => {
                BooleanExpr::Or(Box::new(!*inner_0), Box::new(!*inner_1))
            }
            BooleanExpr::Or(inner_0, inner_1) => {
                BooleanExpr::And(Box::new(!*inner_0), Box::new(!*inner_1))
            }
            BooleanExpr::Xor(inner_0, inner_1) => BooleanExpr::Xor(Box::new(!*inner_0), inner_1),
            BooleanExpr::Mux(mux, inner_0, inner_1) => {
                BooleanExpr::Mux(mux, Box::new(!*inner_0), Box::new(!*inner_1))
            }
        }
    }
}

impl BooleanExpr {
    fn mux_left_true(mux: &Operand, right: &BooleanExpr) -> BooleanExpr {
        match right {
            BooleanExpr::Operand(Operand::True) => BooleanExpr::Operand(Operand::True),
            BooleanExpr::Operand(Operand::False) => BooleanExpr::Operand(*mux),
            _ => BooleanExpr::Or(
                Box::new(BooleanExpr::Operand(*mux)),
                Box::new(right.clone()),
            ),
        }
    }

    fn mux_left_false(mux: &Operand, right: &BooleanExpr) -> BooleanExpr {
        match right {
            BooleanExpr::Operand(Operand::True) => BooleanExpr::Operand(!*mux),
            BooleanExpr::Operand(Operand::False) => BooleanExpr::Operand(Operand::False),
            _ => BooleanExpr::And(
                Box::new(BooleanExpr::Operand(!*mux)),
                Box::new(right.clone()),
            ),
        }
    }

    fn mux_left_x(mux: &Operand, left: &BooleanExpr, right: &BooleanExpr) -> BooleanExpr {
        match right {
            BooleanExpr::Operand(Operand::True) => Self::mux_left_true(&!*mux, left),
            BooleanExpr::Operand(Operand::False) => Self::mux_left_false(&!*mux, left),
            _ if left == right => left.clone(),
            _ if *left == !right.clone() => BooleanExpr::Xor(
                Box::new(BooleanExpr::Operand(!*mux)),
                Box::new(left.clone()),
            ),
            _ => BooleanExpr::Mux(*mux, Box::new(left.clone()), Box::new(right.clone())),
        }
    }

    fn mux(mux: &Operand, left: &BooleanExpr, right: &BooleanExpr) -> BooleanExpr {
        match left {
            BooleanExpr::Operand(Operand::True) => Self::mux_left_true(mux, right),
            BooleanExpr::Operand(Operand::False) => Self::mux_left_false(mux, right),
            _ => Self::mux_left_x(mux, left, right),
        }
    }

    pub fn reduce_mux(items: &Vec<BooleanExpr>) -> BooleanExpr {
        assert!(
            items.len() & (items.len() - 1) == 0,
            "Input was not a power of 2! It was {:?}",
            items.len()
        );

        if items.len() == 0 {
            return BooleanExpr::Operand(Operand::True);
        }

        if items.len() == 1 {
            return items[0].clone();
        }

        let operands = [
            Operand::Bit0,
            Operand::Bit1,
            Operand::Bit2,
            Operand::Bit3,
            Operand::Bit4,
            Operand::Bit5,
            Operand::Bit6,
            Operand::Bit7,
        ];

        let size_log_2: usize =
            (usize::BITS as i32 - (items.len().leading_zeros() as i32)) as usize;

        let result = operands[..size_log_2 - 1]
            .iter()
            .fold(items.clone(), |acc, &operand| {
                acc.array_chunks::<2>()
                    .map(|x| Self::mux(&operand, &x[0], &x[1]))
                    .collect::<Vec<_>>()
            });

        assert!(result.len() == 1, "Something went wrong with the fold");

        result[0].clone()
    }

    pub fn evaluate(
        &self,
        bits: &[Ciphertext],
        true_enc: &Ciphertext,
        server_key: &ServerKey,
        visited: Arc<DashMap<BooleanExpr, Ciphertext>>,
    ) -> Ciphertext {
        assert!(bits.len() == 8, "BITS LENGTH IS INCORRECT");

        if visited.contains_key(self) {
            return visited
                .get(self)
                .expect("The DashMap should contain the current Expr")
                .clone();
        }

        let evaluated_expr = match self {
            BooleanExpr::Operand(op) => op.evaluate(bits, true_enc, server_key),
            BooleanExpr::And(op_1, op_2) => server_key.and(
                &(op_1).evaluate(bits, true_enc, server_key, visited.clone()),
                &op_2.evaluate(bits, true_enc, server_key, visited.clone()),
            ),
            BooleanExpr::Or(op_1, op_2) => server_key.or(
                &(op_1).evaluate(bits, true_enc, server_key, visited.clone()),
                &op_2.evaluate(bits, true_enc, server_key, visited.clone()),
            ),
            BooleanExpr::Xor(op_1, op_2) => server_key.xor(
                &(op_1).evaluate(bits, true_enc, server_key, visited.clone()),
                &op_2.evaluate(bits, true_enc, server_key, visited.clone()),
            ),
            BooleanExpr::Mux(mux, op_1, op_2) => server_key.mux(
                &mux.evaluate(bits, true_enc, server_key),
                &(op_1).evaluate(bits, true_enc, server_key, visited.clone()),
                &op_2.evaluate(bits, true_enc, server_key, visited.clone()),
            ),
        };

        visited.insert(self.clone(), evaluated_expr.clone());
        evaluated_expr
    }

    pub fn from_bool_vec(items: &[bool]) -> Vec<BooleanExpr> {
        items.into_iter().map(|&x| BooleanExpr::from(x)).collect()
    }
}

impl From<bool> for BooleanExpr {
    fn from(value: bool) -> Self {
        BooleanExpr::Operand(value.into())
    }
}
use std::cmp::Ordering;

// impl PartialEq for BooleanExpr {
//     fn eq(&self, other: &Self) -> bool {
//         match self {
//             BooleanExpr::Operand(inner) => match other {
//                 BooleanExpr::Operand(other_inner) => inner == other_inner,
//                 _ => false,
//             },
//             BooleanExpr::And(inner_0, inner_1) => match other {
//                 BooleanExpr::And(other_inner_0, other_inner_1) => {
//                     Self::eq_commutative(&inner_0, &inner_1, &other_inner_0, &other_inner_1)
//                 }
//                 _ => false,
//             },
//             BooleanExpr::Or(inner_0, inner_1) => match other {
//                 BooleanExpr::And(other_inner_0, other_inner_1) => {
//                     Self::eq_commutative(&inner_0, &inner_1, &other_inner_0, &other_inner_1)
//                 }
//                 _ => false,
//             },
//             BooleanExpr::Xor(inner_0, inner_1) => match other {
//                 BooleanExpr::And(other_inner_0, other_inner_1) => {
//                     Self::eq_commutative(&inner_0, &inner_1, &other_inner_0, &other_inner_1)
//                 }
//                 _ => false,
//             },
//             BooleanExpr::Mux(mux, inner_0, inner_1) => match other {
//                 BooleanExpr::Mux(other_mux, other_inner_0, other_inner_1) => {
//                     mux == other_mux && inner_0 == other_inner_0 && inner_1 == other_inner_1
//                 }
//                 _ => false,
//             },
//         }
//     }
// }
impl PartialOrd for Operand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Operand {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl BooleanExpr {
    fn discriminant(&self) -> u8 {
        match self {
            BooleanExpr::Operand(_) => 0,
            BooleanExpr::And(_, _) => 1,
            BooleanExpr::Or(_, _) => 2,
            BooleanExpr::Xor(_, _) => 3,
            BooleanExpr::Mux(_, _, _) => 4,
        }
    }
}

impl PartialOrd for BooleanExpr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BooleanExpr {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare discriminants first
        let self_disc = self.discriminant();
        let other_disc = other.discriminant();
        match self_disc.cmp(&other_disc) {
            Ordering::Equal => {
                // Compare content based on the type
                match (self, other) {
                    (BooleanExpr::Operand(a), BooleanExpr::Operand(b)) => a.cmp(b),
                    (BooleanExpr::And(lhs1, rhs1), BooleanExpr::And(lhs2, rhs2))
                    | (BooleanExpr::Or(lhs1, rhs1), BooleanExpr::Or(lhs2, rhs2))
                    | (BooleanExpr::Xor(lhs1, rhs1), BooleanExpr::Xor(lhs2, rhs2)) => {
                        lhs1.cmp(lhs2).then_with(|| rhs1.cmp(rhs2))
                    }
                    (BooleanExpr::Mux(op1, lhs1, rhs1), BooleanExpr::Mux(op2, lhs2, rhs2)) => op1
                        .cmp(op2)
                        .then_with(|| lhs1.cmp(lhs2))
                        .then_with(|| rhs1.cmp(rhs2)),
                    _ => Ordering::Equal, // Shouldn't reach here
                }
            }
            other_ordering => other_ordering,
        }
    }
}

impl Hash for Operand {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use the discriminant of the enum for a basic hash
        std::mem::discriminant(self).hash(state);
    }
}

impl Hash for BooleanExpr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            BooleanExpr::Operand(op) => {
                0.hash(state); // Discriminant for Operand
                op.hash(state);
            }
            BooleanExpr::And(lhs, rhs) => {
                1.hash(state); // Discriminant for And
                lhs.hash(state);
                rhs.hash(state);
            }
            BooleanExpr::Or(lhs, rhs) => {
                2.hash(state); // Discriminant for Or
                lhs.hash(state);
                rhs.hash(state);
            }
            BooleanExpr::Xor(lhs, rhs) => {
                3.hash(state); // Discriminant for Xor
                lhs.hash(state);
                rhs.hash(state);
            }
            BooleanExpr::Mux(op, t_expr, f_expr) => {
                4.hash(state); // Discriminant for Mux
                op.hash(state);
                t_expr.hash(state);
                f_expr.hash(state);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::time::{Duration, Instant};

    use super::*;
    use tfhe::boolean::gen_keys;
    use tfhe::boolean::prelude::*;

    pub fn bool_to_ciphertext(booleans: &[bool], client_key: &ClientKey) -> Vec<Ciphertext> {
        booleans.iter().map(|&x| client_key.encrypt(x)).collect()
    }

    fn u128_to_bool(mut x: u128, bits: usize) -> Vec<bool> {
        let mut res = vec![];
        for _ in 0..bits {
            res.push(x & 1 != 0);
            x >>= 1;
        }

        res
    }

    fn u256_to_bool(x: u128, y: u128, bits: usize) -> Vec<bool> {
        let mut first_half = u128_to_bool(x, bits / 2);
        let second_half = u128_to_bool(y, bits / 2);

        first_half.extend(second_half);

        first_half
    }

    fn generate_bits(count: u32) -> Vec<Box<Vec<bool>>> {
        let mut res = vec![];
        let base: u128 = 2;
        for x in 0..base.pow(count) {
            let intermediate_res = u128_to_bool(x, count as usize);
            res.push(Box::new(intermediate_res));
        }
        res
    }

    fn mux(mux: bool, left: bool, right: bool) -> bool {
        if mux { left } else { right }
    }

    fn clear_mux_eval(bool_bits: &[bool], truth_table: &[bool]) -> bool {
        assert!(
            truth_table.len() & (truth_table.len() - 1) == 0,
            "Input was not a power of 2!"
        );

        if truth_table.len() == 0 {
            return true;
        }

        if truth_table.len() == 1 {
            return truth_table[0];
        }

        let size_log_2: usize =
            (usize::BITS as i32 - (truth_table.len().leading_zeros() as i32)) as usize;

        let result =
            bool_bits[..size_log_2 - 1]
                .iter()
                .fold(truth_table.to_vec(), |acc, &operand| {
                    acc.array_chunks::<2>()
                        .map(|x| mux(operand, x[0], x[1]))
                        .collect::<Vec<_>>()
                });

        assert!(result.len() == 1, "Something went wrong with the fold");

        result[0]
    }

    #[test]
    fn test_mux_true_1() {
        let expr = BooleanExpr::from_bool_vec(&vec![true]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::True));
    }

    #[test]
    fn test_mux_true_2() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, true]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::True));
    }

    #[test]
    fn test_mux_true_4() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, true, true, true]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::True));
    }

    #[test]
    fn test_mux_true_false() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, false]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::Bit0));
    }

    #[test]
    fn test_mux_true_false_true_false() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, false, true, false]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::Bit0));
    }

    #[test]
    fn test_mux_true_false_false_false() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, false, false, false]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(
            result,
            BooleanExpr::And(
                Box::new(BooleanExpr::Operand(Operand::Bit0)),
                Box::new(BooleanExpr::Operand(Operand::Bit1))
            )
        );
    }

    #[test]
    fn test_evaluate_true() {
        let (client_key, server_key) = gen_keys();
        let bits = bool_to_ciphertext(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let true_enc = client_key.encrypt(true);

        let expr = BooleanExpr::from_bool_vec(&vec![true]);
        let result_expr = BooleanExpr::reduce_mux(&expr);
        let enc_result =
            result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

        assert_eq!(client_key.decrypt(&enc_result), true);
    }

    #[test]
    fn test_evaluate_false() {
        let (client_key, server_key) = gen_keys();
        let bits = bool_to_ciphertext(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let true_enc = client_key.encrypt(true);

        let expr = BooleanExpr::from_bool_vec(&vec![false]);
        let result_expr = BooleanExpr::reduce_mux(&expr);
        let enc_result =
            result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

        assert_eq!(client_key.decrypt(&enc_result), false);
    }

    #[test]
    fn test_evaluate_level_0_true_false() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let expr = BooleanExpr::from_bool_vec(&vec![true, false]);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result =
                result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));
            assert_eq!(client_key.decrypt(&enc_result), bool_bits[0]);
        }
    }

    #[test]
    fn test_evaluate_level_0_false_true() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let expr = BooleanExpr::from_bool_vec(&vec![false, true]);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result =
                result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));
            assert_eq!(client_key.decrypt(&enc_result), !bool_bits[0]);
        }
    }

    #[test]
    fn test_evaluate_level_0_true_true() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let expr = BooleanExpr::from_bool_vec(&vec![true, true]);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result =
                result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));
            assert_eq!(client_key.decrypt(&enc_result), true);
        }
    }

    #[test]
    fn test_evaluate_level_0_false_false() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let truth_table = vec![false, false];
        let expr = BooleanExpr::from_bool_vec(&truth_table);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result =
                result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

            let clear_result = clear_mux_eval(&bool_bits, &truth_table);
            assert_eq!(client_key.decrypt(&enc_result), clear_result);
        }
    }

    #[test]
    fn test_evaluate_level_0() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);

        for truth_table in generate_bits(2) {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8).into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result =
                    result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    fn test_evaluate_level_1() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);

        for truth_table in generate_bits(4) {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8).into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result =
                    result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_2() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let truth_tables = vec![Box::new(vec![
            true, false, true, true, false, false, false, true,
        ])];
        for truth_table in truth_tables {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8)[128..].into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result =
                    result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_5() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let truth_tables = vec![u128_to_bool(23456789 as u128, 64 as usize)];
        for truth_table in truth_tables {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8)[..1].into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result =
                    result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_7() {
        let (client_key, server_key) = gen_keys();
        let true_enc = client_key.encrypt(true);
        let truth_tables = vec![u256_to_bool(23456789 as u128, 234567 as u128, 256 as usize)];
        println!("Hello");
        for truth_table in truth_tables {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            let mut total = Duration::new(0, 0);
            for bool_bits in generate_bits(8)[0..100].into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let start = Instant::now();
                let enc_result =
                    result_expr.evaluate(&bits, &true_enc, &server_key, Arc::new(DashMap::new()));
                total += start.elapsed();

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }

            println!("TIME TAKEN: {:?}", total / 100);
        }
    }
}
