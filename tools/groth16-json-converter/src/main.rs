use groth16_json_converter::convert_files;
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <proof.json> <verification_key.json> <public.json>",
            args[0]
        );
        std::process::exit(2);
    }

    let converted = convert_files(
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    )?;
    println!("{}", serde_json::to_string_pretty(&converted)?);
    Ok(())
}
