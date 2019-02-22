extern crate reqwest;

extern crate serde_json;
use serde_json::Value;

use std::fmt;
use std::collections::HashMap;

#[derive(Default, Deserialize, Debug, Clone)]
struct Msg {
    id: String,
    t: f64,
    from_user: String,
    msg: String,
    #[serde(default)]
    to_user: Option<String>,
    #[serde(default)]
    channel: Option<String>,
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_user.as_ref() {
            Some(v) => write!(
                f,
                "{} - to {} from {}: {}",
                self.t, v, self.from_user, self.msg
            ),
            None => write!(f, "{} - {}: {}", self.t, self.from_user, self.msg),
        }
    }
}

struct ChatReturn {
    status: u8,
    messages: Vec<Msg>
}

#[derive(Deserialize)]
struct SeanResponse {
    chats: HashMap<String, Vec<Msg>>,
    //ok: Value,
}

pub fn hm_loop(time: i64, client: &reqwest::Client, token: String, usernames: Vec<String>) -> Result<Vec<String>, String> {
    let mut msgVec = Vec::new();
    if !token.is_empty() {
        let data = json!({"chat_token": token,
                "usernames":usernames,
                "after":time});
        let mut resp = match client
            .post("https://www.hackmud.com/mobile/chats.json")
            .json(&data)
            .send()
        {
            Ok(x) => x,
            Err(x) => {
                println!("Error querying hm chat API using {}: {}", data, x);
                return Err(format!(
                "Error querying hm chat API using {}: {}", data, x)
                );
            }
        };
        let raw: Value;
        match resp.json() {
            Ok(x) => raw = x,
            Err(x) => {
                println!(
                    "Error parsing as JSON due to {}\n{}",
                    x,
                    resp.text().unwrap()
                );
                return Err(format!("Error parsing as JSON due to {}\n{}",
                x,
                resp.text().unwrap()
                ));
            }
        }
        if !raw["error"].is_null() {
            if raw["error"].as_str().unwrap().contains("authenticate")  {
                println!("Hackmud chat API failure due to bad token");
                return Err("Hackmud chat API failure due to bad token".to_string());
            } else {
                println!("hackmud chat API Error:, {}", raw["error"]);
            }
        } else {
            let r: SeanResponse;
            match serde_json::from_value(raw) {
                Ok(x) => r = x,
                Err(x) => {
                    println!("{}", x);
                    return Err(format!("generic error: {}", x));
                }
            }
            for (name,user) in r.chats.iter() {
                for message in user {
                    if let Some(u) = message.clone().to_user {
                        if &u == name {
                            msgVec.push(format!("{}",message));
                        }
                    }
                }
            }
        }
    }
    Ok(msgVec)
}
