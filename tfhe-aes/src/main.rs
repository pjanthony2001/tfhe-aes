use std::time::{Duration, Instant};
use tfhe::integer::gen_keys_radix;
use tfhe::prelude::*;
use tfhe::shortint::gen_keys;
pub use tfhe::shortint::parameters::classic::gaussian::p_fail_2_minus_64::pbs_ks::{
    PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64, PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64,
};
use tfhe::shortint::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint32, FheUint8, MatchValues,
};

use rayon::prelude::*;

use base::time_trial_mux;

fn print_type<T>(_: &T) {
    println!("{:?}", std::any::type_name::<T>());
}

fn rot_word(word: &FheUint32) -> FheUint32 {
    word.rotate_left(8 as u8)
}

fn sub_word(word: &FheUint32, s_box: &MatchValues<u8>) -> FheUint32 {
    let start_shift_cast = Instant::now();

    let byte1: FheUint8 = (word & 0x000000FF).cast_into();
    let byte2: FheUint8 = ((word >> 8 as u8) & 0x000000FF).cast_into();
    let byte3: FheUint8 = ((word >> 16 as u8) & 0x000000FF).cast_into();
    let byte4: FheUint8 = ((word >> 24 as u8) & 0x000000FF).cast_into();

    let duration_shift_cast = start_shift_cast.elapsed();
    let start_match = Instant::now();

    let (sub_byte1, _): (FheUint8, _) = byte1.match_value(s_box).unwrap();
    let (sub_byte2, _): (FheUint8, _) = byte2.match_value(s_box).unwrap(); // cast into !
    let (sub_byte3, _): (FheUint8, _) = byte3.match_value(s_box).unwrap();
    let (sub_byte4, _): (FheUint8, _) = byte4.match_value(s_box).unwrap();

    let duration_match = start_match.elapsed();
    let start_cast = Instant::now();

    let sub_byte1_32: FheUint32 = sub_byte1.cast_into();
    let sub_byte2_32: FheUint32 = sub_byte2.cast_into();
    let sub_byte3_32: FheUint32 = sub_byte3.cast_into();
    let sub_byte4_32: FheUint32 = sub_byte4.cast_into();

    let duration_cast = start_cast.elapsed();

    println!("SHIFT CAST {:?}", duration_shift_cast);
    println!("MATCH {:?}", duration_match);
    println!("CAST {:?}", duration_cast);

    (((((sub_byte4_32 << 8 as u8) | sub_byte3_32) << 8 as u8) | sub_byte2_32) << 8 as u8)
        | sub_byte1_32
}

fn rotate_left_sub_word(word: &FheUint32, s_box: &MatchValues<u8>) -> FheUint32 {
    let byte1: FheUint8 = ((word >> 24 as u8) & 0x000000FF).cast_into();
    let byte2: FheUint8 = (word & 0x000000FF).cast_into();
    let byte3: FheUint8 = ((word >> 8 as u8) & 0x000000FF).cast_into();
    let byte4: FheUint8 = ((word >> 16 as u8) & 0x000000FF).cast_into();

    let (sub_byte1, _): (FheUint8, _) = byte1.match_value(s_box).unwrap();
    let (sub_byte2, _): (FheUint8, _) = byte2.match_value(s_box).unwrap(); // cast into !
    let (sub_byte3, _): (FheUint8, _) = byte3.match_value(s_box).unwrap();
    let (sub_byte4, _): (FheUint8, _) = byte4.match_value(s_box).unwrap();

    let sub_byte1_32: FheUint32 = sub_byte1.cast_into();
    let sub_byte2_32: FheUint32 = sub_byte2.cast_into();
    let sub_byte3_32: FheUint32 = sub_byte3.cast_into();
    let sub_byte4_32: FheUint32 = sub_byte4.cast_into();

    (((((sub_byte4_32 << 8 as u8) | sub_byte3_32) << 8 as u8) | sub_byte2_32) << 8 as u8)
        | sub_byte1_32
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    time_trial_mux();

    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64);
    // set_server_key(server_key.clone());

    // let word = FheUint32::encrypt(0x12312312 as u32, &client_key);

    let s_box_data: [u64; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ];

    let mut total_time = Duration::new(0, 0);
    for i in 0..1000 {
        let x_enc = client_key.encrypt(i);
        let start = Instant::now();
        server_key.unchecked_bitand(&x_enc, &x_enc);
        total_time += start.elapsed();
    }

    println!("AHSD {:?}", total_time / 1000);

    let s_box_func_0 = |x: u64| s_box_data[x as usize];
    let s_box_func_1 = |x: u64| s_box_data[x as usize] >> 1;
    let s_box_func_2 = |x: u64| s_box_data[x as usize] >> 2;
    let s_box_func_3 = |x: u64| s_box_data[x as usize] >> 3;
    let s_box_func_4 = |x: u64| s_box_data[x as usize] >> 4;
    let s_box_func_5 = |x: u64| s_box_data[x as usize] >> 5;
    let s_box_func_6 = |x: u64| s_box_data[x as usize] >> 6;
    let s_box_func_7 = |x: u64| s_box_data[x as usize] >> 7;

    let s_box_lookup_0 = server_key.generate_lookup_table(s_box_func_0);
    let s_box_lookup_1 = server_key.generate_lookup_table(s_box_func_1);
    let s_box_lookup_2 = server_key.generate_lookup_table(s_box_func_2);
    let s_box_lookup_3 = server_key.generate_lookup_table(s_box_func_3);
    let s_box_lookup_4 = server_key.generate_lookup_table(s_box_func_4);
    let s_box_lookup_5 = server_key.generate_lookup_table(s_box_func_5);
    let s_box_lookup_6 = server_key.generate_lookup_table(s_box_func_6);
    let s_box_lookup_7 = server_key.generate_lookup_table(s_box_func_7);

    let apply_subst_0 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_0);
    let apply_subst_1 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_1);
    let apply_subst_2 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_2);
    let apply_subst_3 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_3);
    let apply_subst_4 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_4);
    let apply_subst_5 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_5);
    let apply_subst_6 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_6);
    let apply_subst_7 = |x: &Ciphertext| server_key.apply_lookup_table(x, &s_box_lookup_7);
    // Create a vector of (key, value) pairs

    let vec: Vec<(_, _)> = (0..=255)
        .map(|key| (key as u8, s_box_data[key as usize] as u8))
        .collect();

    // let start_match = Instant::now();
    let s_box = MatchValues::new(vec).unwrap();
    // let duration_match = start_match.elapsed();

    // let subbed_word = sub_word(&word, &s_box);
    //
    let start = Instant::now();
    let x = client_key.encrypt(0x03);
    let subbed_word_0 = apply_subst_0(&x);
    let subbed_word_1 = apply_subst_1(&x);
    let subbed_word_2 = apply_subst_2(&x);
    let subbed_word_3 = apply_subst_3(&x);
    let subbed_word_4 = apply_subst_4(&x);
    let subbed_word_5 = apply_subst_5(&x);
    let subbed_word_6 = apply_subst_6(&x);
    let subbed_word_7 = apply_subst_7(&x);

    let result_0: u64 = client_key.decrypt(&subbed_word_0);
    let result_1: u64 = client_key.decrypt(&subbed_word_1) << 1;
    let result_2: u64 = client_key.decrypt(&subbed_word_2) << 2;
    let result_3: u64 = client_key.decrypt(&subbed_word_3) << 3;
    let result_4: u64 = client_key.decrypt(&subbed_word_4) << 4;
    let result_5: u64 = client_key.decrypt(&subbed_word_5) << 5;
    let result_6: u64 = client_key.decrypt(&subbed_word_6) << 6;
    let result_7: u64 = client_key.decrypt(&subbed_word_7) << 7;
    println!(
        "BITWISE SUBSTITUTION TIME {:#x} {:?}",
        result_0 ^ result_1 ^ result_2 ^ result_3 ^ result_4 ^ result_5 ^ result_6 ^ result_7,
        start.elapsed()
    );

    let num_block = 2;
    let (client_key_1, server_key_1) =
        gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64, num_block);

    let x: u8 = 0x00;

    let start_radix = Instant::now();
    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key_1.encrypt(x);
    // We use the server public key to execute an integer circuit:
    let (result, _) = server_key_1.match_value_parallelized(&mut ct_1, &s_box);
    // We use the client key to decrypt the output of the circuit:
    let output: u64 = client_key_1.decrypt(&result);

    println!(
        "RADIX SUBSTITUTION TIME {:#x} {:?}",
        output,
        start_radix.elapsed()
    );

    let x: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 1];
    let mut x_enc: Vec<_> = x
        .iter()
        .map(|x_bit| client_key.encrypt(x_bit.clone().into()))
        .collect();

    let shift_1 = |x: u64| x << 1;
    let shift_2 = |x: u64| x << 2;
    let shift_3 = |x: u64| x << 3;
    let shift_4 = |x: u64| x << 4;
    let shift_5 = |x: u64| x << 5;
    let shift_6 = |x: u64| x << 6;
    let shift_7 = |x: u64| x << 7;

    let join_xor = |x: u64, y: u64| x ^ y;

    let shift_lookup_1 = server_key.generate_lookup_table(shift_1);
    let shift_lookup_2 = server_key.generate_lookup_table(shift_2);
    let shift_lookup_3 = server_key.generate_lookup_table(shift_3);
    let shift_lookup_4 = server_key.generate_lookup_table(shift_4);
    let shift_lookup_5 = server_key.generate_lookup_table(shift_5);
    let shift_lookup_6 = server_key.generate_lookup_table(shift_6);
    let shift_lookup_7 = server_key.generate_lookup_table(shift_7);

    let apply_shift_1 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_1);
    let apply_shift_2 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_2);
    let apply_shift_3 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_3);
    let apply_shift_4 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_4);
    let apply_shift_5 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_5);
    let apply_shift_6 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_6);
    let apply_shift_7 = |x: &Ciphertext| server_key.apply_lookup_table(x, &shift_lookup_7);

    let join_lookup = server_key.generate_lookup_table_bivariate(join_xor);
    let apply_join = |x: &Ciphertext, y: &Ciphertext| {
        server_key.apply_lookup_table_bivariate(x, y, &join_lookup)
    };

    let start = Instant::now();
    let shifted_x_1 = apply_shift_1(&x_enc[1]);
    let shifted_x_2 = apply_shift_2(&x_enc[2]);
    let shifted_x_3 = apply_shift_3(&x_enc[3]);
    let shifted_x_4 = apply_shift_4(&x_enc[4]);
    let shifted_x_5 = apply_shift_5(&x_enc[5]);
    let shifted_x_6 = apply_shift_6(&x_enc[6]);
    let shifted_x_7 = apply_shift_7(&x_enc[7]);

    let whole_byte_2 = apply_join(&shifted_x_1, &x_enc[0]);
    let whole_byte_4 = apply_join(&shifted_x_2, &shifted_x_3);
    let whole_byte_6 = apply_join(&shifted_x_4, &shifted_x_5);
    let whole_byte_8 = apply_join(&shifted_x_6, &shifted_x_7);

    let whole_byte_24 = apply_join(&whole_byte_2, &whole_byte_4);
    let whole_byte_68 = apply_join(&whole_byte_6, &whole_byte_8);

    let whole_byte = apply_join(&whole_byte_24, &whole_byte_68);

    let subbed_word_0 = apply_subst_0(&whole_byte);
    let subbed_word_1 = apply_subst_1(&whole_byte);
    let subbed_word_2 = apply_subst_2(&whole_byte);
    let subbed_word_3 = apply_subst_3(&whole_byte);
    let subbed_word_4 = apply_subst_4(&whole_byte);
    let subbed_word_5 = apply_subst_5(&whole_byte);
    let subbed_word_6 = apply_subst_6(&whole_byte);
    let subbed_word_7 = apply_subst_7(&whole_byte);

    // let y = client_key.encrypt(0x01);
    // let subbed_word_0 = apply_subst_0(&y);
    // let subbed_word_1 = apply_subst_1(&y);
    // let subbed_word_2 = apply_subst_2(&y);
    // let subbed_word_3 = apply_subst_3(&y);
    // let subbed_word_4 = apply_subst_4(&y);
    // let subbed_word_5 = apply_subst_5(&y);
    // let subbed_word_6 = apply_subst_6(&y);
    // let subbed_word_7 = apply_subst_7(&y);

    let result_0: u64 = client_key.decrypt(&subbed_word_0);
    let result_1: u64 = client_key.decrypt(&subbed_word_1) << 1;
    let result_2: u64 = client_key.decrypt(&subbed_word_2) << 2;
    let result_3: u64 = client_key.decrypt(&subbed_word_3) << 3;
    let result_4: u64 = client_key.decrypt(&subbed_word_4) << 4;
    let result_5: u64 = client_key.decrypt(&subbed_word_5) << 5;
    let result_6: u64 = client_key.decrypt(&subbed_word_6) << 6;
    let result_7: u64 = client_key.decrypt(&subbed_word_7) << 7;

    println!(
        "FIXED BITWISE SUBSTITUTION TIME {:#x} {:?}",
        result_0 ^ result_1 ^ result_2 ^ result_3 ^ result_4 ^ result_5 ^ result_6 ^ result_7,
        start.elapsed() + start.elapsed()
    );

    println!("MESSAGE MODULUS {:?}", server_key.message_modulus.0 as u64);

    let (client_key_4, server_key_4) = gen_keys(PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64);

    let a = client_key_4.encrypt(0x00);
    let b = client_key_4.encrypt(0x02);
    let join_lookup_0 = |x: u64, y: u64| s_box_data[((x << 4) ^ y) as usize];
    let join_lookup_1 = |x: u64, y: u64| s_box_data[((x << 4) ^ y) as usize] >> 4;

    let join_lut_0 = server_key_4.generate_lookup_table_bivariate(join_lookup_0);
    let apply_join_0 = |x: &Ciphertext, y: &Ciphertext| {
        server_key_4.apply_lookup_table_bivariate(x, y, &join_lut_0)
    };
    let join_lut_1 = server_key_4.generate_lookup_table_bivariate(join_lookup_1);
    let apply_join_1 = |x: &Ciphertext, y: &Ciphertext| {
        server_key_4.apply_lookup_table_bivariate(x, y, &join_lut_1)
    };

    let start = Instant::now();
    let result_0: u64 = client_key_4.decrypt(&apply_join_0(&a, &b));
    let result_1: u64 = client_key_4.decrypt(&apply_join_1(&a, &b)) << 4;
    println!(
        "FIXED AGAIN BITWISE SUBSTITUTION TIME {:#x} {:?}",
        result_0 ^ result_1,
        start.elapsed()
    );

    // let rotated_word = rot_word(&word);
    // println!("MATCHED TIME: {:?}", duration_match);

    // let encrypted: u32 = word.decrypt(&client_key);
    // let decrypted: u32 = subbed_word.decrypt(&client_key);
    // let rotated: u32 = rotated_word.decrypt(&client_key);
    // println!("ENCRYPTED: {:#x},  SUBBED: {:#x}", encrypted, decrypted);
    // println!("ENCRYPTED: {:#x},  ROTATED: {:#x}", encrypted, rotated);

    //  let a = FheUint8::encrypt(0x12 as u8, &client_key);
    // let b = FheUint8::encrypt(0x34 as u8, &client_key);
    // let c = FheUint8::encrypt(0x34 as u8, &client_key);
    // let d = FheUint8::encrypt(0x34 as u8, &client_key);

    // let start_s_box_par = Instant::now();
    // let vec_s: Vec<(u8, FheUint8)> = (0..=255)
    //     .into_par_iter()
    //     .map(|key| {
    //         (
    //             key as u8,
    //             FheUint8::encrypt(s_box_data[key as usize], &client_key),
    //         )
    //     })
    //     .collect();
    // println!("SBOX PAR {:?}", start_s_box_par.elapsed());

    // let start_lookup = Instant::now();
    // let table = LookupTable::new(vec_s, server_key.clone());
    // let result: u8 = table.lookup(&x).decrypt(&client_key);
    // let duration_lookup = start_lookup.elapsed();

    // println!("RESULT {:#x}, TIME: {:?}", result, duration_lookup);

    Ok(())
}
