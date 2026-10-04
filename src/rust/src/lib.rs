mod sha256;

use core::ffi::c_char;
use std::alloc::{alloc as rust_alloc, dealloc as rust_dealloc, Layout};
use std::ffi::CStr;
use sha256::Sha256;

#[inline(always)]
fn imul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b)
}

const ALIGNMENT: usize = 16;
const HEADER_SIZE: usize = 16;

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    let total_size = size.saturating_add(HEADER_SIZE);
    let layout = match Layout::from_size_align(total_size, ALIGNMENT) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let ptr = rust_alloc(layout);
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    *(ptr as *mut usize) = size;
    ptr.add(HEADER_SIZE)
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let orig_ptr = ptr.sub(HEADER_SIZE);
    let size = *(orig_ptr as *const usize);
    let total_size = size.saturating_add(HEADER_SIZE);
    if let Ok(layout) = Layout::from_size_align(total_size, ALIGNMENT) {
        rust_dealloc(orig_ptr, layout);
    }
}

#[no_mangle]
pub unsafe extern "C" fn alloc(size: usize) -> *mut u8 {
    malloc(size)
}

#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, _size: usize) {
    free(ptr);
}

#[inline]
fn cyrb53(bytes: &[u8], seed: u32) -> u64 {
    let mut h1 = (0xdeadbeef_u32 ^ seed) as i32;
    let mut h2 = (0x41c6ce57_u32 ^ seed) as i32;

    for &ch in bytes {
        let c = ch as i8 as i32;
        h1 = imul(h1 ^ c, -1640531535);
        h2 = imul(h2 ^ c, 1597334677);
    }

    h1 = imul(h1 ^ (h1 >> 16), -2048144789) ^ imul(h2 ^ (h2 >> 13), -1028477387);
    h2 = imul(h2 ^ (h2 >> 16), -2048144789) ^ imul(h1 ^ (h1 >> 13), -1028477387);

    let h2_part = ((2097151 & (h2 as u32)) as u64) * 4294967296;
    h2_part + (h1 as u32 as u64)
}

#[no_mangle]
pub unsafe extern "C" fn hash_string(str_ptr: *const c_char) -> u64 {
    if str_ptr.is_null() {
        return 0;
    }
    let c_str = CStr::from_ptr(str_ptr);
    cyrb53(c_str.to_bytes(), 0)
}

fn hex_char_to_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn parse_hex_to_bytes(hex: &[u8], bytes: &mut [u8; 32]) {
    bytes.fill(0);
    let mut byte_idx = 31isize;
    let mut i = hex.len() as isize - 1;
    while i >= 0 && byte_idx >= 0 {
        let low = hex_char_to_val(hex[i as usize]);
        let high = if i > 0 {
            hex_char_to_val(hex[(i - 1) as usize])
        } else {
            0
        };
        bytes[byte_idx as usize] = (high << 4) | low;
        byte_idx -= 1;
        i -= 2;
    }
}

#[inline]
fn format_u32(mut n: u32, buf: &mut [u8; 16]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut idx = 16;
    while n > 0 {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[idx..]
}

#[no_mangle]
pub unsafe extern "C" fn solve_cpu_target(
    base_block_ptr: *const u8,
    base_block_len: i32,
    target_hex_ptr: *const c_char,
) -> i32 {
    if base_block_ptr.is_null() || target_hex_ptr.is_null() || base_block_len <= 0 {
        return 0;
    }
    let base_block = std::slice::from_raw_parts(base_block_ptr, base_block_len as usize);
    let target_hex = CStr::from_ptr(target_hex_ptr).to_bytes();

    let mut target_bytes = [0u8; 32];
    parse_hex_to_bytes(target_hex, &mut target_bytes);

    let mut base_sha = Sha256::new();
    base_sha.update(base_block);

    let mut cpu_solution: u32 = 0;
    let mut hash = [0u8; 32];
    let mut num_buf = [0u8; 16];

    loop {
        let num_slice = format_u32(cpu_solution, &mut num_buf);

        let mut sha = base_sha;
        sha.update(num_slice);
        sha.finalize(&mut hash);

        if hash < target_bytes {
            break;
        }
        cpu_solution = cpu_solution.wrapping_add(1);
    }
    cpu_solution as i32
}

#[no_mangle]
pub unsafe extern "C" fn solve_memory_challenge(seed_ptr: *const c_char, difficulty_mb: i32) -> i32 {
    if seed_ptr.is_null() || difficulty_mb <= 0 {
        return 0;
    }
    let seed = CStr::from_ptr(seed_ptr).to_bytes();
    let size = (difficulty_mb as usize) * 1024 * 1024;
    let buffer_len = size / 4;
    if buffer_len == 0 {
        return 0;
    }

    let mut buffer = Vec::with_capacity(buffer_len);
    let mut h: i32 = seed.iter().map(|&b| b as i32).sum();

    for i in 0..buffer_len {
        h = imul(h ^ (i as i32), 1597334677);
        buffer.push(h as u32);
    }

    let mut solution: i32 = 0;
    let iterations = size / 16;
    let mut addr = (buffer[0] as usize) % buffer_len;

    for _ in 0..iterations {
        addr = (buffer[addr] as usize) % buffer_len;
        solution ^= addr as i32;
    }

    solution
}

fn hash_seed_to_float(seed: &[u8]) -> f32 {
    let mut hash: i32 = 0;
    for &ch in seed {
        hash = (hash << 5).wrapping_sub(hash).wrapping_add(ch as i8 as i32);
    }
    (hash.wrapping_rem(1000000).abs() as f32) / 1000000.0
}

#[no_mangle]
pub unsafe extern "C" fn generate_gpu_pow_trajectory(
    seed_ptr: *const c_char,
    iterations: i32,
    output: *mut f32,
) {
    if seed_ptr.is_null() || output.is_null() {
        return;
    }
    let seed = CStr::from_ptr(seed_ptr).to_bytes();
    let numeric_seed = hash_seed_to_float(seed);
    let r = 3.9999_f32;

    #[cfg(target_feature = "simd128")]
    {
        use core::arch::wasm32::*;
        let r_vec = f32x4_splat(r);
        let one_vec = f32x4_splat(1.0);

        for idx in (0..64).step_by(4) {
            let x0 = (numeric_seed + (idx as f32 + 0.0) * 0.015) % 1.0;
            let x1 = (numeric_seed + (idx as f32 + 1.0) * 0.015) % 1.0;
            let x2 = (numeric_seed + (idx as f32 + 2.0) * 0.015) % 1.0;
            let x3 = (numeric_seed + (idx as f32 + 3.0) * 0.015) % 1.0;

            let mut x_vec = f32x4(x0, x1, x2, x3);
            for _ in 0..iterations {
                let one_minus_x = f32x4_sub(one_vec, x_vec);
                let temp = f32x4_mul(x_vec, one_minus_x);
                x_vec = f32x4_mul(r_vec, temp);
            }
            v128_store(output.add(idx) as *mut v128, x_vec);
        }
    }

    #[cfg(not(target_feature = "simd128"))]
    {
        for idx in 0..64 {
            let mut x = (numeric_seed + (idx as f32) * 0.015) % 1.0;
            for _ in 0..iterations {
                x = r * x * (1.0 - x);
            }
            *output.add(idx) = x;
        }
    }
}