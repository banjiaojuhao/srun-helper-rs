use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use argh::FromArgs;
use chrono::Utc;
use hex;
use md5::Digest;
use reqwest::blocking::Client;
use serde_json::Value;
use sha1::Sha1;

use crate::encrypt::x_encode_str;

mod encrypt;


const HOST_URL: &str = "http://10.248.98.2/cgi-bin/srun_portal";
const CHALLENGE_URL: &str = "http://10.248.98.2/cgi-bin/get_challenge";

#[derive(FromArgs, PartialEq, Debug)]
/// login or logout for srun
struct LoginInfo {
    #[argh(subcommand)]
    action: Action,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Action {
    Login(Login),
    Logout(Logout),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "login")]
/// login srun
struct Login {
    #[argh(option, short = 'u')]
    /// username
    username: String,

    #[argh(option, short = 'p')]
    /// password
    password: String,

    #[argh(option, short = 'I')]
    /// interface address
    interface: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "logout")]
/// logout srun
struct Logout {
    #[argh(option, short = 'u')]
    /// username
    username: String,

    #[argh(option, short = 'I')]
    /// interface address
    interface: Option<String>,
}

fn main() {
    let log_info: LoginInfo = argh::from_env();

    let result = match log_info.action {
        Action::Login(login_config) => {
            let web_client = get_web_client(&login_config.interface);
            login(&web_client, &login_config.username, &login_config.password)
        }
        Action::Logout(logout_config) => {
            let web_client = get_web_client(&logout_config.interface);
            logout(&web_client, &logout_config.username)
        }
    };

    let res_str = result["res"].as_str().unwrap();
    let error_msg_str = result["error_msg"].as_str().unwrap();
    println!("({},{})", res_str, error_msg_str);
}

fn login(web_client: &Client, username: &str, password: &str) -> Value {
    let callback_str = get_callback();
    let challenge = get_challenge(&web_client, username, callback_str.as_str());

    let client_ip = challenge["client_ip"].as_str().unwrap();
    let token = challenge["challenge"].as_str().unwrap();

    let mut user_info: HashMap<&str, &str> = HashMap::new();
    user_info.insert("username", username);
    user_info.insert("password", password);
    user_info.insert("ip", client_ip);
    user_info.insert("ac_id", "1");
    user_info.insert("enc_ver", "srun_bx1");
    let data_json = serde_json::to_string(&user_info).unwrap();

    let mut login_form = HashMap::new();
    login_form.insert("username", username);
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
    digest.update(password.as_bytes());
    let hmd5: String = hex::encode(digest.finalize().iter());
    let md5_str = "{MD5}".to_owned() + &hmd5;
    login_form.insert("password", &md5_str);

    let mut checksum = Sha1::new();
    checksum.update(token.as_bytes());
    checksum.update(username.as_bytes());
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

fn logout(web_client: &Client, username: &str) -> Value {
    let callback: String = get_callback();
    let mut data: HashMap<&str, &str> = HashMap::new();
    data.insert("action", "logout");
    data.insert("username", username);
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

fn get_web_client(interface_config: &Option<String>) -> Client {
    match interface_config {
        None => {
            reqwest::blocking::Client::new()
        }
        Some(local_address) => {
            reqwest::blocking::Client::builder()
                .local_address(IpAddr::from_str(&local_address).unwrap())
                .build()
                .unwrap()
        }
    }
}

fn get_callback() -> String {
    return format!("jsonp{}", Utc::now().timestamp_millis());
}

fn get_challenge(web_client: &Client, username: &str, callback: &str) -> Value {
    let mut data: HashMap<&str, &str> = HashMap::new();
    data.insert("username", username);
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
