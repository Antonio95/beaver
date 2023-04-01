
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

pub fn safe_gen_mod( rng: &mut ChaCha20Rng, q: u32) -> u32 {
    (rng.next_u64() % q as u64) as u32 // cryptographically safer than generating an u32 due to bias

}

pub fn add_without_overflow(a: u32, b: u32, q: u32) -> u32 {
    ((a as u64 + b as u64) % q as u64) as u32
}

pub fn subtract_without_overflow(a: u32, b: u32, q: u32) -> u32 {
    (a as i64 - b as i64).rem_euclid(q as i64) as u32
}

pub fn mul_without_overflow(a: u32, b: u32, q: u32) -> u32 {
    ((a as u64 * b as u64) % q as u64) as u32
}

pub fn modulo(a: i32, q: u32) -> u32 {
    ((a as i64).rem_euclid(q as i64)) as u32
}

pub fn str_u32_to_vec_u32(s: &str) -> Result<Vec<u32>, String> {

    let mut ns = Vec::new();
    for n_str in s.chars().filter(|c| !c.is_whitespace()).collect::<String>().split(",") {
        if n_str.len() > 0 {
            match n_str.parse::<u32>() {
                Ok(n) => {ns.push(n);},
                Err(_) => return Err(format!("Invalid sequence of u32: {s}"))
            }
        }
    }

    Ok(ns)
}

pub fn str_i32_to_vec_u32(s: &str, q: u32) -> Result<Vec<u32>, String> {

    let mut ns = Vec::new();
    for n_str in s.chars().filter(|c| !c.is_whitespace()).collect::<String>().split(",") {
        if n_str.len() > 0 {
            match n_str.parse::<i32>() {
                Ok(n) => {ns.push(modulo(n, q));},
                Err(_) => return Err(format!("Invalid sequence of i32: {s}"))
            }
        }
    }

    Ok(ns)
}
