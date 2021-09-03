use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use hex;
use md5::Digest;
use reqwest::blocking::Client;
use serde_json::Value;
use sha1::Sha1;

use crate::encrypt::x_encode_str;
use std::net::IpAddr;
use std::str::FromStr;

mod encrypt;

struct User {
    username: String,
    password: String,
}

const HOST_URL: &str = "http://10.248.98.2/cgi-bin/srun_portal";
const CHALLENGE_URL: &str = "http://10.248.98.2/cgi-bin/get_challenge";


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: srun-helper-rs login [local address]");
        return;
    };
    let action = args[1].as_str();

    let mut user = String::new();
    File::open("user.txt")
        .expect("failed to open user.txt(username;password)")
        .read_to_string(&mut user)
        .expect("failed to read user.txt");

    let user: Vec<&str> = user.trim().splitn(2, ";").collect();
    if user.len() != 2 {
        println!("invalid user.txt");
        return;
    };
    let user = User {
        username: user[0].trim().to_owned(),
        password: user[1].trim().to_owned(),
    };

    let web_client = if args.len() > 2 {
        let local_address = args[2].as_str();
        reqwest::blocking::Client::builder()
            .local_address(IpAddr::from_str(local_address).unwrap())
            .build()
            .unwrap()
    } else {
        reqwest::blocking::Client::new()
    };

    let result = match action {
        "login" => {
            login(&web_client, &user)
        }
        "logout" => {
            logout(&web_client, &user)
        }
        _ => {
            println!("invalid args. (only \"login\" or \"logout\")");
            return;
        }
    };

    let res_str = result["res"].as_str().unwrap();
    let error_msg_str = result["error_msg"].as_str().unwrap();
    println!("({},{})", res_str, error_msg_str);
}

fn login(web_client: &Client, user: &User) -> Value {
    let callback_str = get_callback();
    let challenge = get_challenge(&web_client, &user, callback_str.as_str());

    let client_ip = challenge["client_ip"].as_str().unwrap();
    let token = challenge["challenge"].as_str().unwrap();

    let mut user_info: HashMap<&str, &str> = HashMap::new();
    user_info.insert("username", user.username.as_str());
    user_info.insert("password", user.password.as_str());
    user_info.insert("ip", client_ip);
    user_info.insert("ac_id", "1");
    user_info.insert("enc_ver", "srun_bx1");
    let data_json = serde_json::to_string(&user_info).unwrap();

    let mut login_form = HashMap::new();
    login_form.insert("username", user.username.as_str());
    login_form.insert("action", "login");
    login_form.insert("n", "200");
    login_form.insert("type", "1");
    login_form.insert("ac_id", "1");
    login_form.insert("callback", callback_str.as_str());
    login_form.insert("ip", client_ip);

    let x_encode_user_data = x_encode_str(&data_json, token);
    let info_str = "{SRBX1}".to_owned() + &x_encode_user_data;
    login_form.insert("info", &info_str);

    let mut digest = md5::Md5::new();
    digest.update(token.as_bytes());
    digest.update(user.password.as_bytes());
    let hmd5: String = hex::encode(digest.finalize().iter());
    let md5_str = "{MD5}".to_owned() + &hmd5;
    login_form.insert("password", &md5_str);

    let mut checksum = Sha1::new();
    checksum.update(token.as_bytes());
    checksum.update(user.username.as_bytes());
    checksum.update(token.as_bytes());
    checksum.update(hmd5.as_bytes());
    checksum.update(token.as_bytes());
    checksum.update(b"1");
    checksum.update(token.as_bytes());
    checksum.update(client_ip.as_bytes());
    checksum.update(token.as_bytes());
    checksum.update(b"200");
    checksum.update(token.as_bytes());
    checksum.update(b"1");
    checksum.update(token.as_bytes());
    checksum.update(info_str.as_bytes());
    let checksum_str: String = hex::encode(checksum.finalize().iter());
    login_form.insert("chksum", &checksum_str);

    let resp = web_client.get(HOST_URL).query(&login_form).send()
        .expect("failed to send request for login");
    let resp_text = resp.text().unwrap();
    let start = resp_text.find("(").unwrap() + 1;
    let end = resp_text.find(")").unwrap();
    let resp_json_text = resp_text[start..end].to_owned();
    let result: Value = serde_json::from_str(&resp_json_text).unwrap();

    return result;
}


fn logout(web_client: &Client, user: &User) -> Value {
    let callback: String = get_callback();
    let mut data: HashMap<&str, &str> = HashMap::new();
    data.insert("action", "logout");
    data.insert("username", user.username.as_str());
    data.insert("ac_id", "1");
    data.insert("ip", "");
    data.insert("callback", callback.as_str());

    let resp = web_client.get(HOST_URL).query(&data).send()
        .expect("failed to send request for logout");
    let resp_text = resp.text().unwrap();
    let start = resp_text.find("(").unwrap() + 1;
    let end = resp_text.find(")").unwrap();
    let resp_json_text = resp_text[start..end].to_owned();
    let result: Value = serde_json::from_str(&resp_json_text).unwrap();

    return result;
}

fn get_callback() -> String {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    return format!("jsonp{}", since_the_epoch.as_millis());
}

fn get_challenge(web_client: &Client, user: &User, callback: &str) -> Value {
    let mut data: HashMap<&str, &str> = HashMap::new();
    data.insert("username", user.username.as_str());
    data.insert("callback", callback);
    let resp = web_client.get(CHALLENGE_URL).query(&data).send()
        .expect("failed to send request for challenge");
    let resp_text = resp.text().unwrap();
    let start = resp_text.find("(").unwrap() + 1;
    let end = resp_text.find(")").unwrap();
    let resp_json_text = resp_text[start..end].to_owned();
    let challenge: Value = serde_json::from_str(&resp_json_text).unwrap();
    return challenge;
}