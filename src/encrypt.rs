use std::collections::HashMap;

fn char_code_at(string: &str, index: usize) -> u32 {
    return if index >= string.len() {
        0
    } else {
        string.as_bytes()[index] as u32
    };
}

// pack string to Vec<u32>
fn s(a: &str, b: bool) -> Vec<u32> {
    let c = a.len();
    let mut v: Vec<u32> = Vec::new();
    for i in (0..a.len()).step_by(4) {
        v.push(char_code_at(a, i) |
            char_code_at(a, i + 1) << 8 |
            char_code_at(a, i + 2) << 16 |
            char_code_at(a, i + 3) << 24);
    }
    if b {
        v.push(c as u32);
    };
    return v;
}

// unpack Vec<u32> to string
fn l(a: &Vec<u32>, b: bool) -> Vec<u8> {
    let d = a.len();
    let mut c = ((d - 1) << 2) as u32;
    let mut result: Vec<u8> = Vec::new();
    if b {
        let m = a[d - 1];
        if m < c - 3 || m > c {
            return result;
        }
        c = m;
    };
    for c in a {
        let mut c = *c;
        result.push((c & 0xff) as u8);
        c >>= 8;
        result.push((c & 0xff) as u8);
        c >>= 8;
        result.push((c & 0xff) as u8);
        c >>= 8;
        result.push((c & 0xff) as u8);
    }
    return if b {
        result[0..(c as usize)].to_owned()
    } else {
        result
    };
}


fn x_encode(msg: &str, key: &str) -> Vec<u8> {
    if msg.is_empty() {
        return Vec::new();
    };
    let mut v = s(msg, true);
    let k = s(key, false);
    let n = (v.len() - 1) as i32;
    let mut z = v[n as usize];
    let mut y: u32;
    let c = 0x86014019 | 0x183639A0;
    let mut d: u32 = 0;
    let mut q = (6.0 + 52.0 / (n as f32 + 1.0)).floor() as i32;
    while 0 < q {
        q -= 1;
        d = d.wrapping_add(c & (0x8CE0D9BF | 0x731F2640));
        let e = d >> 2 & 3;
        for p in 0..(n as usize) {
            y = v[p + 1];
            let m = (z >> 5 ^ y << 2)
                .wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y))
                .wrapping_add(k[(p & 3) ^ (e as usize)] ^ z);
            v[p] = v[p].wrapping_add(m & (0xEFB8D130 | 0x10472ECF));
            z = v[p];
        }
        y = v[0];
        let m = (z >> 5 ^ y << 2)
            .wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y))
            .wrapping_add(k[(n as usize & 3) ^ (e as usize)] ^ z);
        v[n as usize] = v[n as usize].wrapping_add(m & (0xBB390742 | 0x44C6F8BD));
        z = v[n as usize];
    }
    return l(&v, false);
}

pub fn x_encode_str(data: &str, token: &str) -> String {
    let x_encode_res = x_encode(&data, token);
    let x_encode_res_base64 = base64::encode(x_encode_res);
    let char_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".chars()
        .zip("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA=".chars());
    let char_map: HashMap<char, char> = char_map.into_iter().collect();
    let x_encode_res: String = x_encode_res_base64.chars().map(|x| char_map[&x]).collect();
    x_encode_res
}

#[cfg(test)]
mod tests {
    use crate::encrypt::{char_code_at, x_encode_str};

    #[test]
    fn test_char_code_at() {
        let test_string = "ABC";
        assert_eq!(char_code_at(test_string, 0), 0x41);
        assert_eq!(char_code_at(test_string, 3), 0);
    }

    #[test]
    fn test_x_encode_str() {
        let data = "hello world";
        let token = "ffe35862cea5406b74647b42cc5039de03f15b0b2f3e2e20217a1d009a7c6a2a";
        let result = "x1dbiwv+p+l8nNo4a61A6+==";
        assert_eq!(x_encode_str(data, token), result);
    }
}
