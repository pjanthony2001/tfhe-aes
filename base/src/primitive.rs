use std::ops::BitXor;
use std::ops::BitAnd;
use std::cell::RefCell;
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};

use tfhe::boolean::prelude::*;
use tfhe::shortint::client_key;
use tfhe::FheBool;


thread_local! {
    static INTERNAL_KEY: RefCell<Option<ServerKey>> = const { RefCell::new(None) };
    static THREAD_POOL: RefCell<Option<ThreadPool>> = RefCell::new(None);
}

pub fn set_server_key(key: &ServerKey) {
    INTERNAL_KEY.with(|internal_keys| internal_keys.replace_with(|_old| Some(key.clone())));
}

pub fn unset_server_key() {
    INTERNAL_KEY.with(|internal_keys| {
        let _ = internal_keys.replace_with(|_old| None);
    })
}


fn initialize_thread_pool() {
    let parent_server_key = INTERNAL_KEY.with(|thread_data| thread_data.borrow().clone())
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
    data: Vec<Ciphertext>
}

impl FHEByte {
    fn new(bool_data: &[bool], client_key: &ClientKey) -> Self {
        assert!(bool_data.len() == 8, "FHEByte has to be initialized with * booleans !");
        let data = bool_data.into_iter().map(|x| client_key.encrypt(*x)).collect();
        Self{data}
    }

    fn decrypt(&self, client_key: &ClientKey) -> Vec<bool> {
        self.data.iter().map(|x| client_key.decrypt(x)).collect()
    }

    fn xor(&self, rhs: &Self) -> Self {
        let data = THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool.as_ref().expect("ThreadPool has to be initialized before using any operations!");
            let zipped_data: Vec<_> = self.data.iter().zip(rhs.data.iter()).collect();

            pool.install(move || {
                zipped_data.into_par_iter().map(|(x, y)| {
                    INTERNAL_KEY.with_borrow(|maybe_server_key| {
                        let server_key = maybe_server_key.as_ref().expect("ThreadPool should have initialized and cloned ServerKey");
                        server_key.xor(x, y)
                    })
                }).collect()
            })
        });

        FHEByte{data}
    }

    fn and(&self, rhs: &Self) -> Self {
        let data = THREAD_POOL.with_borrow(|maybe_pool| {
            let pool = maybe_pool.as_ref().expect("ThreadPool has to be initialized before using any operations!");
            let zipped_data: Vec<_> = self.data.iter().zip(rhs.data.iter()).collect();

            pool.install(move || {
                zipped_data.into_par_iter().map(|(x, y)| {
                    INTERNAL_KEY.with_borrow(|maybe_server_key| {
                        let server_key = maybe_server_key.as_ref().expect("ThreadPool should have initialized and cloned ServerKey");
                        server_key.and(x, y)
                    })
                }).collect()
            })
        });

        FHEByte{data}       
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

        let x = FHEByte::new(&vec![true, true, true, true, true, true, true, true], &client_key);
        let y = FHEByte::new(&vec![true, false, true, false, true, true, true, true], &client_key);
        let mut z = FHEByte::new(&vec![true, false, true, false, true, true, true, true], &client_key);
        
        let mut val = FHEByte::new(&vec![true, true, true, true, true, true, true, true], &client_key);
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


        assert!(val.decrypt(&client_key) == vec![false, true, false, true, false, false, false, false]);
        assert_eq!(z.decrypt(&client_key), vec![false, true, false, true, false, false, false, false]);
    }


    #[test]
    fn test_and() {
        let (client_key, server_key) = gen_keys();
        set_server_key(&server_key);
        initialize_thread_pool();

        let x = FHEByte::new(&vec![true, true, true, true, true, true, true, true], &client_key);
        let y = FHEByte::new(&vec![true, false, true, false, true, true, true, true], &client_key);
        let mut z = FHEByte::new(&vec![true, false, true, false, true, true, true, true], &client_key);
        
        let mut val = FHEByte::new(&vec![true, true, true, true, true, true, true, true], &client_key);
        let start = Instant::now();
        for _ in 0..1 {
            val = x.and(&y);
        }
        println!("BORROW_PARALLEL_AND {:?}", start.elapsed() / 1);

        let start = Instant::now();
        for _ in 0..1 {
            z = x.clone() & y.clone();
        }
        println!("CONSUME_PARALLEL_AND {:?}", start.elapsed() / 1);


        assert!(val.decrypt(&client_key) == vec![true, false, true, false, true, true, true, true]);
        assert_eq!(z.decrypt(&client_key), vec![true, false, true, false, true, true, true, true]);
    }
}

