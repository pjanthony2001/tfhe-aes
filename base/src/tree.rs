use std::convert::TryFrom;
use std::time::{Duration, Instant};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;

#[derive(Debug, Clone, Copy, EnumIter)]
enum Level_0 {
    True,
    False,
    Bit_0,
    Not_Bit_0,
}

impl Level_0 {
    fn left_true(right: bool) -> Level_0 {
        match right {
            true => Level_0::True,
            false => Level_0::Bit_0,
        }
    }

    fn left_false(right: bool) -> Level_0 {
        match right {
            true => Level_0::Not_Bit_0,
            false => Level_0::False,
        }
    }

    fn apply(left: bool, right: bool) -> Level_0 {
        match left {
            true => Self::left_true(right),
            false => Self::left_false(right),
        }
    }

    fn to_cipher_text(
        self,
        bit_0: &Ciphertext,
        true_enc: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match self {
            Level_0::True => true_enc.clone(),
            Level_0::False => server_key.not(true_enc),
            Level_0::Bit_0 => bit_0.clone(),
            Level_0::Not_Bit_0 => server_key.not(bit_0),
        }
    }
}

#[derive(Debug, Clone, Copy, EnumIter)]
enum Level_1 {
    True,
    False,
    Bit_0,
    Not_Bit_0,

    Bit_1,
    Not_Bit_1,

    Bit_1_XOR_Bit_0,
    Bit_1_XNOR_Bit_0,

    Bit_1_OR_Bit_0,
    Bit_1_NOR_Bit_0,
    Bit_1_AND_Bit_0,
    Bit_1_NAND_Bit_0,

    Bit_1_AND_Not_Bit_0,
    Bit_1_NAND_Not_Bit_0,
    Bit_1_OR_Not_Bit_0,
    Bit_1_NOR_Not_Bit_0,
}

impl Level_1 {
    fn left_true(right: Level_0) -> Level_1 {
        match right {
            Level_0::True => Level_1::True,
            Level_0::False => Level_1::Bit_1,
            Level_0::Bit_0 => Level_1::Bit_1_OR_Bit_0,
            Level_0::Not_Bit_0 => Level_1::Bit_1_OR_Not_Bit_0,
        }
    }

    fn left_false(right: Level_0) -> Level_1 {
        match right {
            Level_0::True => Level_1::Not_Bit_1,
            Level_0::False => Level_1::False,
            Level_0::Bit_0 => Level_1::Bit_1_NOR_Not_Bit_0,
            Level_0::Not_Bit_0 => Level_1::Bit_1_NOR_Bit_0,
        }
    }

    fn left_bit_0(right: Level_0) -> Level_1 {
        match right {
            Level_0::True => Level_1::Bit_1_NAND_Not_Bit_0,
            Level_0::False => Level_1::Bit_1_AND_Bit_0,
            Level_0::Bit_0 => Level_1::Bit_0,
            Level_0::Not_Bit_0 => Level_1::Bit_1_XNOR_Bit_0,
        }
    }

    fn left_not_bit_0(right: Level_0) -> Level_1 {
        match right {
            Level_0::True => Level_1::Bit_1_NAND_Bit_0,
            Level_0::False => Level_1::Bit_1_AND_Not_Bit_0,
            Level_0::Bit_0 => Level_1::Bit_1_XOR_Bit_0,
            Level_0::Not_Bit_0 => Level_1::Not_Bit_0,
        }
    }

    fn apply(left: Level_0, right: Level_0) -> Level_1 {
        match left {
            Level_0::True => Self::left_true(right),
            Level_0::False => Self::left_false(right),
            Level_0::Bit_0 => Self::left_bit_0(right),
            Level_0::Not_Bit_0 => Self::left_not_bit_0(right),
        }
    }

    fn to_cipher_text(
        &self,
        bit_0: &Ciphertext,
        bit_1: &Ciphertext,
        true_enc: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let result_cast: Result<Level_0, _> = (*self).try_into();

        if let Ok(level_0) = result_cast {
            level_0.to_cipher_text(bit_0, true_enc, server_key)
        } else {
            match self {
                Self::Bit_1 => bit_1.clone(),
                Self::Not_Bit_1 => server_key.not(bit_1),

                Self::Bit_1_XOR_Bit_0 => server_key.xor(bit_1, bit_0),
                Self::Bit_1_XNOR_Bit_0 => server_key.xnor(bit_1, bit_0),

                Self::Bit_1_OR_Bit_0 => server_key.or(bit_1, bit_0),
                Self::Bit_1_NOR_Bit_0 => server_key.nor(bit_1, bit_0),
                Self::Bit_1_AND_Bit_0 => server_key.and(bit_1, bit_0),
                Self::Bit_1_NAND_Bit_0 => server_key.nand(bit_1, bit_0),

                Self::Bit_1_AND_Not_Bit_0 => server_key.and(bit_1, &server_key.not(bit_0)),
                Self::Bit_1_NAND_Not_Bit_0 => server_key.nand(bit_1, &server_key.not(bit_0)),
                Self::Bit_1_OR_Not_Bit_0 => server_key.or(bit_1, &server_key.not(bit_0)),
                Self::Bit_1_NOR_Not_Bit_0 => server_key.nor(bit_1, &server_key.not(bit_0)),

                _ => panic!("NOT COVERED BY BASE TYPE ENUM"),
            }
        }
    }
}

impl TryFrom<Level_1> for Level_0 {
    type Error = ();

    fn try_from(level_1: Level_1) -> Result<Self, Self::Error> {
        match level_1 {
            Level_1::True => Ok(Level_0::True),
            Level_1::False => Ok(Level_0::False),
            Level_1::Bit_0 => Ok(Level_0::Bit_0),
            Level_1::Not_Bit_0 => Ok(Level_0::Not_Bit_0),
            _ => Err(()),
        }
    }
}

fn reduce_4(leaves: &Vec<bool>) -> Vec<Level_1> {
    leaves
        .chunks(4)
        .map(|x| (Level_0::apply(x[0], x[1]), Level_0::apply(x[2], x[3])))
        .map(|(x, y)| Level_1::apply(x, y))
        .collect()
}

fn to_ciphertext(
    level_1: &Vec<Level_1>,
    bit_0: &Ciphertext,
    bit_1: &Ciphertext,
    true_enc: &Ciphertext,
    server_key: &ServerKey,
) -> Vec<Ciphertext> {
    level_1
        .iter()
        .map(|x| Level_1::to_cipher_text(x, bit_0, bit_1, true_enc, server_key))
        .collect()
}

pub fn reduce(
    leaves: &Vec<bool>,
    bits: &Vec<Ciphertext>,
    true_enc: &Ciphertext,
    server_key: &ServerKey,
) -> Ciphertext {
    let level_1 = reduce_4(leaves);
    let all_variants: Vec<_> = Level_1::iter()
        .map(|x| Level_1::to_cipher_text(&x, &bits[0], &bits[1], true_enc, server_key))
        .collect();

    let start = Instant::now();
    let level_2_cipher = level_1
        .iter()
        .map(|x| match x {
            Level_1::True => &all_variants[0],
            Level_1::False => &all_variants[1],
            Level_1::Bit_0 => &all_variants[2],
            Level_1::Not_Bit_0 => &all_variants[3],

            Level_1::Bit_1 => &all_variants[4],
            Level_1::Not_Bit_1 => &all_variants[5],

            Level_1::Bit_1_XOR_Bit_0 => &all_variants[6],
            Level_1::Bit_1_XNOR_Bit_0 => &all_variants[7],

            Level_1::Bit_1_OR_Bit_0 => &all_variants[8],
            Level_1::Bit_1_NOR_Bit_0 => &all_variants[9],
            Level_1::Bit_1_AND_Bit_0 => &all_variants[10],
            Level_1::Bit_1_NAND_Bit_0 => &all_variants[11],

            Level_1::Bit_1_AND_Not_Bit_0 => &all_variants[12],
            Level_1::Bit_1_NAND_Not_Bit_0 => &all_variants[13],
            Level_1::Bit_1_OR_Not_Bit_0 => &all_variants[14],
            Level_1::Bit_1_NOR_Not_Bit_0 => &all_variants[15],
        })
        .collect::<Vec<_>>();
    println!("HELP {:?}", start.elapsed());

    let start = Instant::now();
    // let level_2_cipher = to_ciphertext(&level_1, &bits[0], &bits[1], true_enc, server_key); // has 64 to_ciphertext
    println!("HELPE 2 {:?}", start.elapsed());

    let start = Instant::now();
    let result = level_2_cipher
        .clone()
        .into_iter()
        .array_chunks::<2>()
        .map(|x| server_key.mux(&bits[2], &x[0], &x[1]))
        .collect::<Vec<_>>()
        .array_chunks::<2>()
        .map(|x| server_key.mux(&bits[3], &x[0], &x[1]))
        .collect::<Vec<_>>()
        .array_chunks::<2>()
        .map(|x| server_key.mux(&bits[4], &x[0], &x[1]))
        .collect::<Vec<_>>()
        .array_chunks::<2>()
        .map(|x| server_key.mux(&bits[5], &x[0], &x[1]))
        .collect::<Vec<_>>()
        .array_chunks::<2>()
        .map(|x| server_key.mux(&bits[6], &x[0], &x[1]))
        .collect::<Vec<_>>()
        .array_chunks::<2>()
        .map(|x| server_key.mux(&bits[7], &x[0], &x[1]))
        .collect::<Vec<_>>()
        .pop()
        .unwrap();

    println!(
        "SIZE: {:?} TEST SPEED: {:?}",
        level_2_cipher.len(),
        start.elapsed()
    );
    result
}
