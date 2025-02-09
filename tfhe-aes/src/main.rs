use clap::Parser;
use hex;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit, KeyInit, StreamCipher, generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;
use rand::Rng;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'n', long = "number-of-outputs", default_value_t = 1)]
    number_of_outputs: u8,

    #[arg(short, long)]
    iv: String,

    #[arg(short, long)]
    key: String,

    #[arg(short = 'x', long = "key-expansion-offline", default_value_t = false)]
    key_expansion_offline: bool,

    #[arg(short, long, default_value = "CTR")]
    mode: String,
}

enum Mode {
    ECB,
    CBC,
    CTR,
}

const BLOCK_SIZE_IN_BYTES: usize = 16;


fn main() {
    // Example: .\tfhe_aes.exe --number-of-outputs 11 --iv 11111111111111111111111111111111 --key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  --mode ECB
    let args = Args::parse();

    println!("Number of Outputs: {}", args.number_of_outputs);
    println!("IV: {}", args.iv);
    println!("Key: {}", args.key);
    println!("Key Expansion Offline: {}", args.key_expansion_offline);
    println!("Mode: {}", args.mode);

    let key = parse_hex_16(&args.key).expect("Invalid key format");
    let iv = parse_hex_16(&args.iv).expect("Invalid IV format");
    println!("Parsed Key: {:?}", key);
    println!("Parsed IV: {:?}", iv);

    let mut rng = rand::thread_rng();
    let random_blocks: Vec<[u8; 16]> = (0..args.number_of_outputs)
        .map(|_| rng.gen::<[u8; 16]>())
        .collect();

    let plaintext = *b"hello world! this is my plaintext.";
    let mode = parse_mode(&args.mode);
    let ciphertext = aes_clear_encrypt(&plaintext, key, iv, mode);
    println!("Ciphertext: {:?}", ciphertext);
}

fn parse_mode(input: &str) -> Result<Mode, String> {
    match input {
        "ECB" => Ok(Mode::ECB),
        "CBC" => Ok(Mode::CBC),
        "CTR" => Ok(Mode::CTR),
        _ => Err(format!("Invalid mode: {}", input)),
    }
}

fn parse_hex_16(hex_str: &str) -> Result<[u8; 16], String> {
    if hex_str.len() != 32 {
        return Err(format!("Must be 32 hex characters (16 bytes), it is currently {} characters.", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|_| "Failed to decode hex")?;
    let mut array = [0u8; 16];
    array.copy_from_slice(&bytes[..16]);
    Ok(array)
}

fn aes_clear_encrypt(plaintext: &[u8], key: [u8; 16], iv: [u8; 16], mode: Result<Mode, String>) -> Vec<u8> {
    match mode {
        Ok(Mode::CBC) => aes_clear_encrypt_cbc(&plaintext, key, iv),
        Ok(Mode::CTR) => aes_clear_encrypt_ctr(&plaintext, key, iv),
        Ok(Mode::ECB) => aes_clear_encrypt_ecb(&plaintext, key),
        Err(e) => panic!("Failed to determine mode: {:?}", e),
    }
}

fn aes_clear_encrypt_cbc(plaintext: &[u8], key: [u8; 16], iv: [u8; 16]) -> Vec<u8> {
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let pt_len = plaintext.len();
    let buffer_size = ((pt_len + BLOCK_SIZE_IN_BYTES - 1) / BLOCK_SIZE_IN_BYTES) * BLOCK_SIZE_IN_BYTES;
    let mut buf = vec![0u8; buffer_size];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
    .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
    .unwrap();
    ct.to_vec()
}

fn aes_clear_encrypt_ctr(plaintext: &[u8], key: [u8; 16], iv: [u8; 16]) -> Vec<u8> {
    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut buf = plaintext.to_vec();
    let mut cipher = Aes128Ctr64LE::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut buf);
    return buf;
}

fn aes_clear_encrypt_ecb(plaintext: &[u8], key: [u8; 16]) -> Vec<u8> {
    let cipher = Aes128::new(&GenericArray::from(key));

    let pt_len = plaintext.len();
    let padding_size = 16 - (pt_len % 16);
    let mut padded_plaintext = Vec::from(plaintext);

    padded_plaintext.extend(vec![0u8; padding_size]);

    let mut ciphertext = Vec::with_capacity(padded_plaintext.len());
    for chunk in padded_plaintext.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk); 
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }
    ciphertext
}