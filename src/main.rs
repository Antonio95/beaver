
use std::{process::exit, fs::File};
use std::io::{self, BufRead, BufReader};

mod circuit;
mod protocol;
mod sharing;
mod utilities;

fn main() {

    let mut args = std::env::args();

    args.next();

    let input_path = args.next();
    if input_path == None {
        eprintln!("Error: the first argument should be the input path");
        exit(1);
    }
    let output_path = args.next();
    if output_path == None {
        eprintln!("Error: the second argument should be the output path (including filename without extension)");
        exit(1);
    }

    let input_path = input_path.unwrap();
    let output_path = output_path.unwrap();

    let input_file = File::open(input_path);
    if input_file.is_err() {
        eprintln!("Error opening input file")
    }
    
    let mut lines = BufReader::new(input_file.unwrap()).lines();

    let mut circuit_encoding = String::new();

    loop {
        let l = lines.next();
        match l {
            None => {eprintln!("Input file error: the circuit should be followed by more data"); exit(1)},
            Some(Ok(s)) => {
                if s.is_empty() {
                    break;
                } else {
                    circuit_encoding.push_str(&s);
                }
            }
            _ => {eprintln!("Error reading input file"); exit(1)},
        }
    }

    let q: u32 = match lines.next() {
        Some(Ok(s)) => {
            match s.parse() {
                Ok(n) => n,
                Err(_) => {eprintln!("Error reading input file: could not parse q"); exit(1)}
            }
        },
        _ => {eprintln!("Error reading input file at line corresponding to q"); exit(1)},
    };

    let inputs_p1_first = read_input_vector(lines.next(), q);
    let inputs_p1_second = read_input_vector(lines.next(), q);
    let inputs_p2_first = read_input_vector(lines.next(), q);
    let inputs_p2_second = read_input_vector(lines.next(), q);
    
    let authenticated = read_boolean(lines.next(), "for circuit authentication");
    let corrupt = read_boolean(lines.next(), "for party corruption");

    if lines.next().is_some() {
        eprintln!("Error reading input file: unexpected lines after authentication parameter");
        exit(1);
    }

    if let Err(e) = protocol::run_beaver_protocol(
        &circuit_encoding,
        q,
        inputs_p1_first,
        inputs_p1_second,
        inputs_p2_first,
        inputs_p2_second,
        authenticated,
        corrupt,
        &output_path,
    ) {
        eprintln!("{e}");
        exit(1);
    } else {
        println!("Finished successfully")
    }

}

fn read_input_vector(line: Option<io::Result<String>>, q: u32) -> Vec<u32> {
    match line {
        None => {eprintln!("Error reading input file: expected vector of input indices"); exit(1);},
        Some(Ok(s)) => match utilities::str_i32_to_vec_u32(&s, q) {
            Ok(v) => v,
            Err(_) => {eprintln!("Error reading input file: incorrect format for vector of input indices"); exit(1)},
        }
        _ => {eprintln!("Error reading input file"); exit(1)},
    }
}

fn read_boolean(line: Option<io::Result<String>>, msg: &str) -> bool {
    match line {
        Some(Ok(s)) => match s.as_str() {
            "true" => true,
            "false" => false,
            _ => {eprintln!("Input file error: expected \"true\" or \"false\" {}", msg); exit(1)},
        },
        _ => {eprintln!("Input file error: expected \"true\" or \"false\" for {}", msg); exit(1)},
    }
}
