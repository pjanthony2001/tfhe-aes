#![feature(iter_array_chunks)]
#![feature(array_chunks)]
#![feature(ptr_internals)] 

use rayon::prelude::*;
use rayon::scope;
use std::borrow::Borrow;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tfhe::prelude::*;

use rand::Rng;
use std::ptr;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::*;

mod boolean_tree;
mod primitive;
mod sbox;
mod state;
mod tree;

#[derive(Clone, Copy, Debug)]
enum Token {
    True,
    False,
    Bit_0,
    Not_Bit_0,
    Bit_1,
    Not_Bit_1,

    XOR,
    XNOR,
    OR,
    NOR,
    AND,
    NAND,

    MUX,
    NMUX,
}

impl Token {
    fn neg_bool(vec: &Vec<Self>) -> Vec<Self> {
        vec.iter()
            .map(|x| match x {
                Token::True => Token::False,
                Token::False => Token::True,
                _ => *x,
            })
            .collect()
    }
    fn neg_bit_0(vec: &Vec<Self>) -> Vec<Self> {
        vec.iter()
            .map(|x| match x {
                Token::Not_Bit_0 => Token::Bit_0,
                Token::Bit_0 => Token::Not_Bit_0,
                _ => *x,
            })
            .collect()
    }
    fn neg_bit_1(vec: &Vec<Self>) -> Vec<Self> {
        vec.iter()
            .map(|x| match x {
                Token::Bit_1 => Token::Not_Bit_1,
                Token::Not_Bit_1 => Token::Bit_1,
                _ => *x,
            })
            .collect()
    }

    fn neg_token_vector(token: &Token, vec: &Vec<Token>) -> Vec<Token> {
        match token {
            Token::True => Self::neg_bool(vec),
            Token::False => Self::neg_bool(vec),
            Token::Bit_0 => Self::neg_bit_0(vec),
            Token::Not_Bit_0 => Self::neg_bit_0(vec),
            Token::Bit_1 => Self::neg_bit_1(vec),
            Token::Not_Bit_1 => Self::neg_bit_1(vec),
            _ => panic!("IS NOT SUPPOSED TO BE OPERATOR"),
        }
    }

    fn neg_token(token: &Token) -> Token {
        match token {
            Token::True => Token::False,
            Token::False => Token::True,
            Token::Bit_0 => Token::Not_Bit_0,
            Token::Not_Bit_0 => Token::Bit_0,
            Token::Bit_1 => Token::Not_Bit_1,
            Token::Not_Bit_1 => Token::Bit_1,
            Token::XOR => Token::XNOR,
            Token::XNOR => Token::XOR,
            Token::OR => Token::NOR,
            Token::NOR => Token::OR,
            Token::AND => Token::NAND,
            Token::NAND => Token::AND,
            Token::MUX => Token::NMUX,
            Token::NMUX => Token::MUX,
        }
    }
    fn neg_expr(vec: &Vec<Self>) -> Vec<Self> {
        let mut vec_clone = vec.clone();
        if let Some(token) = vec_clone.pop() {
            let neg_token = Self::neg_token(&token);
            vec_clone.push(neg_token);
            vec_clone
        } else {
            vec![]
        }
    }
    fn is_operator(x: &Self) -> bool {
        match x {
            Token::XOR
            | Token::XNOR
            | Token::OR
            | Token::NOR
            | Token::AND
            | Token::NAND
            | Token::MUX
            | Token::NMUX => true,
            Token::True
            | Token::False
            | Token::Bit_0
            | Token::Not_Bit_0
            | Token::Bit_1
            | Token::Not_Bit_1 => false,
        }
    }

    fn is_operand(x: &Self) -> bool {
        !Self::is_operator(x)
    }
}

#[derive(Debug, Clone, Copy)]
struct Level1 {}

impl Level1 {
    fn left_true(mux: &Token, right: &Token) -> Vec<Token> {
        if Token::is_operator(&right) {
            panic!("IS NOT SUPPOSED TO BE OPERATOR");
        }

        match right {
            Token::True => vec![Token::True],
            Token::False => vec![*mux],
            _ => vec![*mux, *right, Token::OR],
        }
    }

    fn left_false(mux: &Token, right: &Token) -> Vec<Token> {
        if Token::is_operator(&right) {
            panic!("IS NOT SUPPOSED TO BE OPERATOR");
        }

        match right {
            Token::True => Token::neg_token_vector(mux, &Self::left_true(mux, &Token::False)),
            Token::False => vec![Token::False],
            _ => vec![*mux, Token::neg_token(right), Token::NOR],
        }
    }

    fn left_bit_x(mux: &Token, left: &Token, right: &Token) -> Vec<Token> {
        if Token::is_operator(&right) {
            panic!("IS NOT SUPPOSED TO BE OPERATOR");
        }

        let neg_left = Token::neg_token(left);
        let neg_mux = Token::neg_token(mux);

        match right {
            Token::True => Token::neg_token_vector(mux, &Self::left_true(mux, left)),
            Token::False => Token::neg_token_vector(mux, &Self::left_false(mux, left)),
            left => vec![*left],
            neg_left => vec![*mux, *left, Token::XNOR],
            mux => vec![*mux, *left, Token::AND],
            neg_mux => vec![*neg_mux, *left, Token::OR],
            _ => vec![*mux, *left, *right, Token::MUX],
        }
    }
}

//TODO: CONVERT EVERYTHING TO VEC<TOKEN> instead so that I can negate the whole vector and then
pub fn time_trial_mux() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys();

    // // We use the client secret key to encrypt two messages:
    //
    let mut total_time = Duration::new(0, 0);
    for i in 0..1000 {
        let ct_1 = client_key.encrypt(true);

        let ct_2 = client_key.encrypt(false);
        let ct_3 = client_key.encrypt(true);

        let start = Instant::now();
        ct_3.clone();
        total_time += start.elapsed();
    }
    //
    //
    //     let mut rng = rand::thread_rng();
    //     let random_tuples: Vec<(bool, bool, bool)> = (0..1000)
    //         .map(|_| (            rng.gen_bool(0.5),  // Generate a random boolean with 50% probability
    //             rng.gen_bool(0.5),
    //             rng.gen_bool(0.5))) // Random booleans
    //         .collect();
    //
    //     // Step 2: Apply the first function (sequentially)
    //     let enc_bits: Vec<_> = random_tuples.iter()
    //         .map(|(a, b, c)| (client_key.encrypt(*a), client_key.encrypt(*b), client_key.encrypt(*c))) // Applying function1
    //         .collect();
    //
    //     // Step 3: Apply the second function (in parallel using Rayon)
    //     let start = Instant::now();
    //     enc_bits.par_iter() // Parallel iteration
    //         .map(|(a, b, c)| server_key.mux(&a, &b, &c)) // Applying function2
    //         .collect::<Vec<_>>();
    //
    println!("CLONE TIME: {:?}", total_time / 1000);
    // println!("TEXT PAR MUX {:?}", start.elapsed() / 1000);

    let key_0 = client_key.encrypt(false);
    let key_1 = client_key.encrypt(true);
    let true_enc = client_key.encrypt(true);

    let leaves = vec![true, true, false, true];
    let leaves_: Vec<_> = leaves.into_iter().cycle().take(256).collect();
    let bits = vec![
        client_key.encrypt(true),
        client_key.encrypt(true),
        client_key.encrypt(true),
        client_key.encrypt(true),
        client_key.encrypt(true),
        client_key.encrypt(true),
        client_key.encrypt(true),
        client_key.encrypt(true),
    ];

    let start = Instant::now();
    for _ in 0..2 {
        tree::reduce(&leaves_, &bits, &true_enc, &server_key);
    }
    println!("TIME TAKEN REDUCE 4 {:?}", start.elapsed() / 2);

    println!(
        "LEFT HANDED MUX {:?}",
        client_key.decrypt(&server_key.mux(&key_1, &key_1, &key_0))
    );

    let enc_true = client_key.encrypt(true);
    let enc_false = client_key.encrypt(false);
    let not_key_0 = server_key.not(&key_0);
    let mux_bit_1 = server_key.mux(&key_1, &key_0, &not_key_0);
    let not_mux_bit_1 = server_key.not(&mux_bit_1);
    let mux_bit_1_bit_0_0 = server_key.mux(&key_1, &key_0, &enc_false);
    let mux_bit_1_bit_0_1 = server_key.mux(&key_1, &key_0, &enc_true);
    let not_mux_bit_1_bit_0_0 = server_key.not(&mux_bit_1_bit_0_0);
    let not_mux_bit_1_bit_0_1 = server_key.not(&mux_bit_1_bit_0_1);

    let tree_leaves: Vec<bool> = vec![true, true, true, false];
    let result: Vec<_> = tree_leaves
        .chunks(2)
        .map(|x| (x[0], x[1]))
        .map(|(x, y)| match (x, y) {
            (false, false) => &enc_false,
            (true, false) => &key_0,
            (false, true) => &not_key_0,
            (true, true) => &enc_true,
        })
        .collect::<Vec<&Ciphertext>>()
        .chunks(2)
        .map(|x| (x[0], x[1]))
        .map(|(x, y)| {
            if ptr::eq(x, &key_0) && ptr::eq(y, &key_0) {
                &key_0
            } else if ptr::eq(x, &not_key_0) && ptr::eq(y, &not_key_0) {
                &not_key_0
            } else if ptr::eq(x, &key_0) && ptr::eq(y, &not_key_0) {
                &mux_bit_1
            } else if ptr::eq(x, &not_key_0) && ptr::eq(y, &key_0) {
                &not_mux_bit_1
            } else if ptr::eq(x, &not_key_0) && ptr::eq(y, &enc_true) {
                &not_mux_bit_1_bit_0_0
            } else if ptr::eq(x, &not_key_0) && ptr::eq(y, &enc_false) {
                &not_mux_bit_1_bit_0_1
            } else if ptr::eq(x, &key_0) && ptr::eq(y, &enc_true) {
                &mux_bit_1_bit_0_1
            } else if ptr::eq(x, &key_0) && ptr::eq(y, &enc_false) {
                &mux_bit_1_bit_0_0
            } else {
                panic!("HELP SOMETHING WENT WRONG");
            }
        })
        .collect();
    println!("result len {:?}", client_key.decrypt(result[0]));
}
