use clap::Parser;

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

    #[arg(short, long)]
    mode: String,
}

fn main() {
    // Example usage: .\clapper.exe -n 2 --iv 111111111111111111111111111111 --key 123 --key-expansion-offline --mode transform  

    let args = Args::parse();

    println!("Number of Outputs: {}", args.number_of_outputs);
    println!("IV: {}", args.iv);
    println!("Key: {}", args.key);
    println!("Key Expansion Offline: {}", args.key_expansion_offline);
    println!("Mode: {}", args.mode);
}