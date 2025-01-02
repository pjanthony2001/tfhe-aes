use crate::boolean_tree::Operand;
use dashmap::DashMap;
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::cell::RefCell;
use std::ops::BitXor;
use std::ops::{BitAnd, BitOr, Not};
use std::rc::Rc;
use std::sync::Arc;

use std::collections::VecDeque;
use tfhe::boolean::prelude::*;

use crate::boolean_tree::BooleanExpr;
use crate::sbox::*;

thread_local! {
    static INTERNAL_KEY: RefCell<Option<ServerKey>> = const { RefCell::new(None) };
    static THREAD_POOL: RefCell<Option<ThreadPool>> = RefCell::new(None);
    static S_BOX_EXPR: RefCell<Vec<BooleanExpr>> = RefCell::new(generate_reduced_bool_expr());
}

pub fn set_server_key(key: &ServerKey) {
    INTERNAL_KEY.with(|internal_keys| internal_keys.replace_with(|_old| Some(key.clone())));
}

pub fn unset_server_key() {
    INTERNAL_KEY.with(|internal_keys| {
        let _ = internal_keys.replace_with(|_old| None);
    })
}

pub fn initialize_thread_pool() {
    let parent_server_key = INTERNAL_KEY
        .with(|thread_data| thread_data.borrow().clone())
        .expect("Server Key is not set ! Failed to initialize ThreadPool");

    THREAD_POOL.with(|pool| {
        let mut pool_ref = pool.borrow_mut();
        if pool_ref.is_none() {
            *pool_ref = Some(
                ThreadPoolBuilder::new()
                    .start_handler(move |thread_index| {
                        set_server_key(&parent_server_key);
                    })
                    .build()
                    .expect("Failed to initialize ThreadPool"),
            );
        }
    })
}

#[derive(Clone)]
pub struct FHEByte {
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

    pub fn decrypt(&self, client_key: &ClientKey) -> Vec<bool> {
        self.data.iter().map(|x| client_key.decrypt(x)).collect()
    }

    pub fn xor(&self, rhs: &Self) -> Self {
        //TODO: Convert to in place versions, using assign, add clear version
        let data = THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool
                .as_ref()
                .expect("ThreadPool has to be initialized before using any operations!");
            let zipped_data: Vec<_> = self.data.iter().zip(rhs.data.iter()).collect();

            pool.install(move || {
                zipped_data
                    .into_par_iter()
                    .map(|(x, y)| {
                        INTERNAL_KEY.with_borrow(|maybe_server_key| {
                            let server_key = maybe_server_key
                                .as_ref()
                                .expect("ThreadPool should have initialized and cloned ServerKey");
                            server_key.xor(x, y)
                        })
                    })
                    .collect()
            })
        });

        FHEByte { data }
    }

    pub fn and(&self, rhs: &Self) -> Self {
        //TODO: Convert to in place versions, using assign
        let data = THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool
                .as_ref()
                .expect("ThreadPool has to be initialized before using any operations!");
            let zipped_data: Vec<_> = self.data.iter().zip(rhs.data.iter()).collect();

            pool.install(move || {
                zipped_data
                    .into_par_iter()
                    .map(|(x, y)| {
                        INTERNAL_KEY.with_borrow(|maybe_server_key| {
                            let server_key = maybe_server_key
                                .as_ref()
                                .expect("ThreadPool should have initialized and cloned ServerKey");
                            server_key.and(x, y)
                        })
                    })
                    .collect()
            })
        });

        FHEByte { data }
    }

    fn or(&self, rhs: &Self) -> Self {
        //TODO: Convert to in place versions, using assign
        let data = THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool
                .as_ref()
                .expect("ThreadPool has to be initialized before using any operations!");
            let zipped_data: Vec<_> = self.data.iter().zip(rhs.data.iter()).collect();

            pool.install(move || {
                zipped_data
                    .into_par_iter()
                    .map(|(x, y)| {
                        INTERNAL_KEY.with_borrow(|maybe_server_key| {
                            let server_key = maybe_server_key
                                .as_ref()
                                .expect("ThreadPool should have initialized and cloned ServerKey");
                            server_key.or(x, y)
                        })
                    })
                    .collect()
            })
        });

        FHEByte { data }
    }

    fn not(&self) -> Self {
        //TODO: Convert to in place versions, using assign
        let data = THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool
                .as_ref()
                .expect("ThreadPool has to be initialized before using any operations!");
            let data = self.data.clone();

            pool.install(move || {
                data.par_iter()
                    .map(move |x| {
                        INTERNAL_KEY.with_borrow(|maybe_server_key| {
                            let server_key = maybe_server_key
                                .as_ref()
                                .expect("ThreadPool should have initialized and cloned ServerKey");
                            server_key.not(x)
                        })
                    })
                    .collect()
            })
        });

        FHEByte { data }
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

    fn shift_right_in_place(&mut self, shift: usize) -> () {
        //TODO: Convert to fixed size array
        let shift = shift.clamp(0, 8);
        INTERNAL_KEY.with_borrow(|maybe_server_key| {
            let server_key = maybe_server_key
                .as_ref()
                .expect("ThreadPool should have initialized and cloned ServerKey");
            for _ in 0..shift {
                self.data.push_front(server_key.trivial_encrypt(false));
                self.data.pop_back();
            }
        })
    }

    fn shift_left_in_place(&mut self, shift: usize) -> () {
        //TODO: Convert to fixed size array
        let shift = shift.clamp(0, 8);
        INTERNAL_KEY.with_borrow(|maybe_server_key| {
            let server_key = maybe_server_key
                .as_ref()
                .expect("ThreadPool should have initialized and cloned ServerKey");
            for _ in 0..shift {
                self.data.push_back(server_key.trivial_encrypt(false));
                self.data.pop_front();
            }
        })
    }

    fn shift_left(&self, shift: usize) -> Self {
        let mut result = self.clone();
        result.shift_left_in_place(shift);
        result
    }

    fn shift_right(&self, shift: usize) -> Self {
        let mut result = self.clone();
        result.shift_right_in_place(shift);
        result
    }

    fn trivial_false() -> Self {
        INTERNAL_KEY.with_borrow(|maybe_server_key| {
            let server_key = maybe_server_key
                .as_ref()
                .expect("ThreadPool should have initialized and cloned ServerKey");
            FHEByte {
                data: std::iter::repeat(server_key.trivial_encrypt(false))
                    .take(8)
                    .collect(),
            } // TODO: Write this better, but Ciphertext doesn't impl Copy trait
        })
    }
    fn trivial_clear(clear_value: u8) -> Self {
        INTERNAL_KEY.with_borrow(|maybe_server_key| {
            let server_key = maybe_server_key
                .as_ref()
                .expect("ThreadPool should have initialized and cloned ServerKey");
            let data = (0..8)
                .into_iter()
                .map(|shift| server_key.trivial_encrypt(clear_value << shift != 0))
                .collect();
            FHEByte { data }
        })
    }
    fn _sub_byte(&self) -> Self {
        //TODO: After staged execution, this should be removed. Old iterator version.
        let visited = Arc::new(DashMap::new());

        let data = S_BOX_EXPR.with_borrow(|s_box_exprs| {
            s_box_exprs
                .iter()
                .map(move |x| {
                    let mut curr_data = self.data.clone();
                    let curr_visited = visited.clone();
                    INTERNAL_KEY.with_borrow(|maybe_server_key| {
                        let server_key = maybe_server_key
                            .as_ref()
                            .expect("ThreadPool should have initialized and cloned ServerKey");
                        x.evaluate(
                            curr_data.make_contiguous(),
                            &server_key.trivial_encrypt(true),
                            server_key,
                            curr_visited,
                        )
                    })
                })
                .collect()
        });

        FHEByte { data }
    }

    pub fn sub_byte(&self) -> Self {
        //TODO: Do staged evaluation.
        let visited = Arc::new(DashMap::new());
        THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool.as_ref().unwrap();
            let data = S_BOX_EXPR.with_borrow(|s_box_exprs| {
                pool.install(|| {
                    s_box_exprs
                        .par_iter()
                        .map(move |x| {
                            let mut curr_data = self.data.clone();
                            let curr_visited = visited.clone();
                            INTERNAL_KEY.with_borrow(|maybe_server_key| {
                                let server_key = maybe_server_key.as_ref().expect(
                                    "ThreadPool should have initialized and cloned ServerKey",
                                );
                                x.evaluate(
                                    curr_data.make_contiguous(),
                                    &server_key.trivial_encrypt(true),
                                    server_key,
                                    curr_visited,
                                )
                            })
                        })
                        .collect()
                })
            });

            FHEByte { data }
        })
    }

    pub fn mul_x_gf2(&mut self) -> Self {
        //TODO: Convert xor to in place versions, using assign and replace the xor, add clear version
        self.shift_left_in_place(1);
        let irr_poly = FHEByte::trivial_clear(0x1b);
        self.xor(&irr_poly)
    }
}

impl BitXor for FHEByte {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(&rhs)
    }
}

impl BitAnd for FHEByte {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.and(&rhs)
    }
}

impl BitOr for FHEByte {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.or(&rhs)
    }
}

impl Not for FHEByte {
    type Output = Self;

    fn not(self) -> Self::Output {
        (&self).not()
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
        initialize_thread_pool();

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );
        let mut z = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut val = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let start = Instant::now();
        for _ in 0..1000 {
            val = x.xor(&y);
        }
        println!("BORROW_PARALLEL_XOR {:?}", start.elapsed() / 1000);

        let start = Instant::now();
        for _ in 0..1000 {
            z = x.clone() ^ y.clone();
        }
        println!("CONSUME_PARALLEL_XOR {:?}", start.elapsed() / 1000);

        assert!(
            val.decrypt(&client_key) == vec![false, true, false, true, false, false, false, false]
        );
        assert_eq!(z.decrypt(&client_key), vec![
            false, true, false, true, false, false, false, false
        ]);
    }

    #[test]
    fn test_and() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        initialize_thread_pool();

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );
        let mut z = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut val = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let start = Instant::now();
        for _ in 0..1000 {
            val = x.and(&y);
        }
        println!("BORROW_PARALLEL_AND {:?}", start.elapsed() / 1000);

        let start = Instant::now();
        for _ in 0..1000 {
            z = x.clone() & y.clone();
        }
        println!("CONSUME_PARALLEL_AND {:?}", start.elapsed() / 1000);

        assert!(val.decrypt(&client_key) == vec![true, false, true, false, true, true, true, true]);
        assert_eq!(z.decrypt(&client_key), vec![
            true, false, true, false, true, true, true, true
        ]);
    }

    #[test]
    fn test_sub_byte() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        initialize_thread_pool();

        let x = FHEByte::new(
            &vec![false, false, false, false, false, false, false, false],
            &client_key,
        );

        let start = Instant::now();

        let mut y: Vec<FHEByte> = vec![];
        for _ in 0..1 {
            y = (0..100)
                .into_iter()
                .map(|_| x.sub_byte())
                .collect::<Vec<_>>();
        }

        println!("CONSUME_PARALLEL_AND {:?}", start.elapsed() / 100);

        assert_eq!(y[0].decrypt(&client_key), vec![
            true, true, true, true, true, true, true, true
        ])
    }
}
