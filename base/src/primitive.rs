

use crate::boolean_tree::Operand;
use dashmap::DashMap;
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::cell::RefCell;
use std::ops::BitXor;
use std::ops::{BitAnd, BitOr, Not};
use std::rc::Rc;
use std::sync::Arc;

use num_cpus;
use std::collections::VecDeque;
use tfhe::boolean::prelude::*;
use tfhe::boolean::server_key::*;

use std::time::Instant;

use crate::boolean_tree::BooleanExpr;
use crate::sbox::*;
use rayon::Scope;



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
    println!("NUM THREADS: {:?}", num_cpus::get());

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

#[inline(always)]
fn with_thread_pool<F>(func: F)
where
    F: FnOnce(&ThreadPool) + std::marker::Send,
{
    THREAD_POOL.with_borrow(|maybe_pool| {
        let pool = maybe_pool.as_ref()
            .expect("ThreadPool should be initialized before any parallel tasks");
        pool.install(|| func(pool));
    });
}

#[inline(always)]
fn with_server_key<F>(func: F)
where
    F: FnOnce(&ServerKey),
{
    INTERNAL_KEY.with_borrow(|maybe_server_key| {
        let server_key = maybe_server_key.as_ref()
            .expect("ThreadPool should have initialized and cloned ServerKey");
        func(server_key);
    });
}

#[derive(Clone, Debug)]
pub struct FHEByte { // TODO: REDO WITH THE DAMN FOR EACH WITH instead of FOR EACH !!!!!!!!!!!!!! and see if there is any marginal improvement.
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

    pub fn xor_in_place(&mut self, rhs: &Self, pool: &ThreadPool) {
        let zipped_data: Vec<_> = self.data.iter_mut().zip(rhs.data.iter()).collect();

        pool.install(move || {
            zipped_data
                .into_par_iter()
                .for_each(|(x, y)| with_server_key(|server_key: &ServerKey| server_key.xor_assign(x, y)))
        })
    }

    pub fn xor(&self, rhs: &Self, pool: &ThreadPool) -> Self {
        let mut result = self.clone();
        result.xor_in_place(rhs, pool);
        result
    }

    pub fn and_in_place(&mut self, rhs: &Self, pool: &ThreadPool) {
        let zipped_data: Vec<_> = self.data.iter_mut().zip(rhs.data.iter()).collect();

        pool.install(move || {
            zipped_data
                .into_par_iter()
                .for_each(|(x, y)| with_server_key(|server_key: &ServerKey| server_key.and_assign(x, y)))
        })
    }

    pub fn and(&self, rhs: &Self, pool: &ThreadPool) -> Self {
        let mut result = self.clone();
        result.and_in_place(rhs, pool);
        result
    }

    pub fn or_in_place(&mut self, rhs: &Self, pool: &ThreadPool) {
        let zipped_data: Vec<_> = self.data.iter_mut().zip(rhs.data.iter()).collect();

        pool.install(move || {
            zipped_data
                .into_par_iter()
                .for_each(|(x, y)| with_server_key(|server_key: &ServerKey| server_key.or_assign(x, y)))
        })
    }

    pub fn or(&self, rhs: &Self, pool: &ThreadPool) -> Self {
        let mut result = self.clone();
        result.or_in_place(rhs, pool);
        result
    }

    pub fn not_in_place(&mut self, pool: &ThreadPool) {
        pool.install(move || {
            self.data
                .par_iter_mut()
                .for_each(|x| with_server_key(|server_key: &ServerKey| server_key.not_assign(x)))
        })
    }

    pub fn not(&self, pool: &ThreadPool) -> Self {
        let mut result = self.clone();
        result.not_in_place(pool);
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

    fn shift_right_in_place(&mut self, shift: usize) -> () {
        //TODO: Convert to fixed size array
        let shift = shift.clamp(0, 8);
        with_server_key(|server_key: &ServerKey| {
            for _ in 0..shift {
                self.data.push_front(server_key.trivial_encrypt(false));
                self.data.pop_back();
            }
        })
    }

    fn shift_left_in_place(&mut self, shift: usize) -> () {
        //TODO: Convert to fixed size array
        let shift = shift.clamp(0, 8);

        with_server_key(|server_key: &ServerKey| {
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

    fn trivial_false() -> Self {
        Self::trivial_clear(0)
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

    pub fn mul_x_gf2_in_place(&mut self, pool: &ThreadPool) {
        self.shift_left_in_place(1);
        let irr_poly = FHEByte::trivial_clear(0x1b);
        self.xor_in_place(&irr_poly, pool)
    }

    pub fn mul_x_gf2(&self, pool: &ThreadPool) -> Self {
        //TODO: Convert xor to in place versions, using assign and replace the xor, add clear version
        let mut result = self.clone();
        result.mul_x_gf2_in_place(pool);
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
        initialize_thread_pool();

        let mut x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );



        let mut test_data: Vec<_> = (0..200).into_iter().map(|_| x.clone()).collect();
        let start = Instant::now();
            with_thread_pool (|pool| {
                    test_data
                        .iter_mut()
                        .for_each(|x| {
                            x.xor_in_place(&y, pool)
                        })
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
        initialize_thread_pool();

        let x = FHEByte::new(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );
        let y = FHEByte::new(
            &vec![true, false, true, false, true, true, true, true],
            &client_key,
        );

        let mut x_cipher = client_key.encrypt(false);
        let y_cipher = client_key.encrypt(true);

        let start = Instant::now();
        for _ in 0..1000 {
            server_key.and_assign(&mut x_cipher, &y_cipher);
        }
        println!("NON-Parallel AND {:?}", start.elapsed() / 1000);

        let mut test_data: Vec<_> = (0..4).into_iter().map(|_| x.clone()).collect();
        let start = Instant::now();
        with_thread_pool (|pool| {
                test_data
                    .par_iter_mut()
                    .map(|x| x.and_in_place(&y, pool))
                    .collect::<Vec<_>>();
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
