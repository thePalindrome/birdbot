extern crate reqwest;
extern crate serenity;
extern crate chrono;
extern crate regex;
extern crate serde;
extern crate env_logger;
extern crate typemap;

#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
extern crate postgres;

mod hm;
mod skullgirls;

static mut THREADED: bool = false;

use serenity::Client;
use serenity::prelude::*;
use serenity::model::prelude::*;
use serenity::CACHE;

use serde_json::Value;

use std::env;
use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use std::thread;
use std::sync::Arc;

use regex::Regex;

use chrono::prelude::*;

use postgres::{Connection, TlsMode};

use typemap::Key;


struct DbKey;
impl Key for DbKey { type Value = Arc<Mutex<Connection>>; }

#[derive(Deserialize, Serialize, Debug)]
struct Reminder {
reminder_text: String,
                   reminder_time: DateTime<Utc>,
                   repeat_length: u64,
                   user: UserId,
                   channel: ChannelId,
}

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    reminders: Vec<Reminder>,
}

struct BirdbotUser {
    id: i64,
    hm_tok: Option<String>,
    hm_usernames: Option<Vec<String>>,
    is_admin: bool
}

impl Config {
    fn flush(&self) {
        let str = serde_json::to_string_pretty(self).unwrap();
        let mut f = File::create("/etc/birdbot").unwrap(); // TODO: Maybe make sure nobody touched it before we wipe it?
        f.write(str.as_bytes()).unwrap();
    }
}

struct Handler {
config: Arc<Mutex<Config>>,
}

impl Handler {
    fn new() -> Self {
        let f = File::open("/etc/birdbot").expect("/etc/birdbot doesn't exist?"); // TODO: Remove the old config system after migrating reminders
        let config;
        match serde_json::from_reader(f) {
            Ok(x) => config = x,
                Err(x) => {
                    println!("Config read err: {}", x);
                    config = Config {
                        reminders: Vec::new(),
                    }
                }
        };
        Self {
config: Arc::new(Mutex::new(config)),
        }
    }
}

fn paying_attention(msg: &Message) -> bool{
    // Check if I'm in a DM, being mentioned, or otherwise has been requested
    if msg.is_own() {
        return false; // Don't react to my own messages, please
    }
    /*if msg.content.contains("birdbot") { // TODO: Allow disabling just using my name
      return true;
      }*/
    if msg.mentions.iter().any( |x| { x.id == CACHE.read().user.id }) {
        return true;
    }
    if msg.is_private() {
        return true;
    }
    false
}

impl EventHandler for Handler {
    fn message(&self, ctx: Context, msg: Message) {
        if paying_attention(&msg) {
            lazy_static! {
                static ref remind_regex: Regex = Regex::new("remind me (.*) in (\\d* \\w*)( every (\\d* \\w*))?").unwrap();
                static ref factor_regex: Regex = Regex::new("factor (.\\d*)").unwrap();
                static ref skullgirls_regex: Regex = Regex::new("[Pp]lay a game with (.*) (against|vs.|vs) (.*)").unwrap();
            }

            let user = {

                    let data = ctx.data.lock();
                    let conn = data.get::<DbKey>().expect("AAAA").lock();
                    let mut rows = conn.query("SELECT * FROM users WHERE id = $1",  &[&(*msg.author.id.as_u64() as i64)]).unwrap();
                    let row = { if rows.is_empty() {
                            conn.execute("INSERT INTO users (id) VALUES ($1)", &[&(*msg.author.id.as_u64() as i64)]);
                            rows = conn.query("SELECT * FROM users WHERE id = $1", &[&(*msg.author.id.as_u64() as i64)]).unwrap();
                        }
                        rows.get(0)
                    };

                BirdbotUser {
                    id: row.get("id"),
                    hm_tok: row.get("hm_tok"),
                    hm_usernames: row.get("hm_usernames"),
                    is_admin: row.get("is_admin")
                }
            };

            let mut command_list = msg.content.clone();

            if skullgirls_regex.is_match(&command_list) { // Play a round
                let list_copy = &command_list.clone();
                let captures = skullgirls_regex.captures(list_copy).unwrap(); // Safe because is_match

                let player_1_str = str::replace(captures.get(1).unwrap().as_str(), ",", "");
                let player_2_str = str::replace(captures.get(3).unwrap().as_str(), ",", "");

                for player in player_1_str.split(" ") {
                }

                for player in player_2_str.split(" ") {
                } // Alright, now we have our players

                msg.reply(&skullgirls::simulate_fight(vec!(player_1_str),vec!(player_2_str)));
            }

            if remind_regex.is_match(&command_list) { // reminder handling
                let list_copy = &command_list.clone();
                let reminder = remind_regex.captures(list_copy).unwrap(); // Safe because I used is_match

                let remind_text = reminder.get(1).unwrap().as_str();
                let time_delay: Vec<&str> = reminder.get(2).unwrap().as_str().split(" ").collect();

                if time_delay.len() != 2 {
                    msg.author.direct_message(|m| m.content("Unable to parse time to remind."));
                }

                if let Ok(num) = time_delay[0].parse::<f64>() {
                    let sec_multi: f64 = match time_delay[1].to_lowercase().as_str() {
                            "seconds" => 1.0,
                            "secs" => 1.0,
                            "minutes" => 60.0,
                            "minute" => 60.0,
                            "hours" => 3600.0,
                            "hour" => 3600.0,
                            "days" => 86400.0,
                            "day" => 86400.0,
                            "weeks" => 604800.0,
                            "week" => 604800.0,
                            "months" => 2419200.0,
                            "month" => 2419200.0,
                            "years" => 31449600.0,
                            "year" => 31449600.0,
                            _ => { msg.author.direct_message(|m| m.content("Invalid measurement of time")); 0.0},
                    };
                    if sec_multi != 0.0 {
                        let remind_time = Utc::now() + chrono::Duration::seconds( (num * sec_multi).floor() as i64 );
                        msg.reply(&format!("Ok, I will remind you {} around {}.",remind_text,remind_time.format("%a %b %d %Y %T UTC")));
                        self.config.lock().reminders.push(Reminder {
reminder_text: remind_text.to_string(),
reminder_time: remind_time,
repeat_length: 0,
user: msg.author.id,
channel: msg.channel_id
});
self.config.lock().flush();
}
}
command_list = command_list.replace(reminder.get(0).unwrap().as_str(),"");
}

if factor_regex.is_match(&command_list) {
    if let Ok(mut composite) = factor_regex.captures(&command_list).unwrap().get(1).unwrap().as_str().parse::<u64>() {
        if composite == 1 || composite == 2 {
            msg.reply("That's... not how this works.");
        }
        let mut factors: Vec<u64> = Vec::new();
        while composite % 2 == 0 {
            composite /= 2;
            factors.push(2);
        }
        let mut f = 3;
        while f * f <= composite {
            if composite % f == 0 {
                factors.push(f);
                composite /= f;
            } else {
                f += 2;
            }
        }
        if composite != 1 { 
            factors.push(composite); 
        }
        let mut reply: String = "`".to_string();
        if factors.len() > 1 {
            let mut cur_factor: &u64 = factors.first().unwrap();
            let mut times_repeated = 1;
            for i in factors.iter().skip(1) {
                if i != cur_factor {
                    if times_repeated != 1 {
                        reply.push_str(&format!(" {}^{} *",cur_factor,times_repeated));
                        times_repeated = 1;
                    } else {
                        reply.push_str(&format!(" {} *",cur_factor));
                    }
                    cur_factor = i;
                } else {
                    times_repeated += 1;
                }
            }
            if times_repeated != 1 {
                reply.push_str(&format!(" {}^{} *", cur_factor, times_repeated));
                times_repeated = 1;
            } else {
                reply.push_str(&format!(" {} *", cur_factor));
            }
            let length = reply.len();
            reply.truncate(length-2);
            reply.push('`');
        } else {
            reply = format!("`{} is a prime number`",factors.first().unwrap());
        }
        msg.reply(&reply);
    } else {
        msg.reply("Unable to parse factor");
    }
    command_list = command_list.replace(factor_regex.captures(&command_list).unwrap().get(0).unwrap().as_str(),"");
}

if command_list.contains("help") {
    msg.reply("Current commands: `remind me X in Y time_units`\n`factor <u64>`");
}

if user.is_admin == true  { // If is_admin
    if command_list.contains("away") {
        ctx.idle();
    } else if command_list.starts_with("/who ") {
        let a: Vec<&str> = command_list.split(' ').collect();
        if a.len() != 2 {
            let _ = msg.author.direct_message(|m| m.content("/who <UID>"));
            return;
        }
        let foo: u64 = match a[1].parse() {
            Ok(x) => x,
                Err(e) => {
                    let _ = msg.author
                        .direct_message(|m| m.content(format!("Unable to format: {}", e)));
                    return;
                }
        };
        match UserId(foo).to_user() {
            Ok(x) => msg.reply(&format!("{}",x.name)),
            Err(x) => msg.reply(&format!("{:?}", x))
        };
        return;
    } else if command_list.contains("plzdienow") {
        let _ = ctx.shard.shutdown_clean();
        return;
    } else if command_list.starts_with("/auth ") {
        let a: Vec<&str> = command_list.split(' ').collect();
        if a.len() != 2 {
            msg.author
                .direct_message(|m| m.content("Try `/auth <hackmud_pass>`"))
                .unwrap();
            return;
        }
        let data = json!({"pass": a[1]});
        let mut resp = reqwest::Client::new()
            .post("https://www.hackmud.com/mobile/get_token.json")
            .json(&data)
            .send()
            .unwrap();
        let raw: Value = match resp.json() {
            Ok(x) => x,
                Err(e) => {
                    let _ = msg.author
                        .direct_message(|m| m.content(format!("failed to parse: {}", e)));
                    return;
                }
        };
        if raw["chat_token"].is_string() {
            let foo = String::from_str(raw["chat_token"].as_str().unwrap()).unwrap();

                let data = ctx.data.lock();
                // TODO: Ensure that a username list is configured!
                {
                    let conn = data.get::<DbKey>().expect("Unable to get DB!").lock();
                    if let Ok(_x) = conn.execute("UPDATE users SET hm_tok=$1 WHERE id=$2", &[&foo, &user.id]) {
                        let _ = msg.react("✅");
                    }
                }
            
        } else {
            msg.author.direct_message(|m| m.content(format!("Error: {}",raw)));
        }
    }
}
}
}

fn ready(&self, ctx: Context, _: Ready) {
    let client = reqwest::Client::new();
    let local_safe_var = unsafe { THREADED };
    if local_safe_var == false {
        ctx.set_game(Game::listening("the conversation"));
        ctx.idle();
        unsafe {
            THREADED = true;
        }
        let config = Arc::clone(&self.config);
        let conn = Arc::clone(ctx.data.lock().get::<DbKey>().expect("AAAA"));
        thread::spawn(move || {
                let mut time = Utc::now().timestamp() - 31;
                loop {
                {
                let mut conf = config.lock();

                for hm_user in conn.lock().query("SELECT id, hm_tok, hm_usernames FROM users WHERE hm_tok IS NOT NULL", &[]).unwrap().iter() {
                    let uid: i64 = hm_user.get(0);
                    let user = UserId(uid as u64).to_user().unwrap(); // TODO: Delete the hm_tok if this operation fails, since I can't contact them.
                    match hm::hm_loop(time, &client, hm_user.get(1), hm_user.get(2)) {
                        Ok(x) => {
                            for i in x {
                                let _ = user.direct_message(|m| m.content(i));
                            }},
                        Err(e) => {let _ = user.direct_message(|m| m.content(e));},
                    }
                }

                let cur_time = Utc::now();
                let mut expired_reminders: Vec<usize> = Vec::new();
                for (index, reminder) in conf.reminders.iter().enumerate() {
                    if reminder.reminder_time < cur_time {
                        let text = serenity::utils::content_safe(&reminder.reminder_text, {&serenity::utils::ContentSafeOptions::default()});
                        match reminder.channel.to_channel() {
                            Ok(thing) => {
                                    if let Err(e) = thing.id().say(&format!("{} Don't forget {}", reminder.user.mention(), text)) {
                                        println!("Failed to send message to {} : {}", reminder.channel, reminder.reminder_text);
                                    }
                            },   
                            Err(e) => { 
                                if let Ok(dm) = reminder.user.create_dm_channel() {
                                    dm.say(&format!("{} Don't forget {}", reminder.user.mention(), reminder.reminder_text));
                                } else {
                                    println!("Failed to send DM to {} : {}", reminder.user.mention(), reminder.reminder_text);
                                }
                            }
                        }
                        expired_reminders.push(index);
                    }
                }

                let mut offset = 0;
                for i in expired_reminders.iter() {
                    conf.reminders.remove(i - offset);
                    offset += 1;
                }

                conf.flush();
                }

                thread::sleep(chrono::Duration::seconds(30).to_std().unwrap());
                time += 30;
                }
        });
    }
}
}

fn main() {
    env_logger::init();
    info!("Becoming real...");
    let token = env::var("DISCORD_TOKEN").expect("Please set DISCORD_TOKEN to the login token");

    let conn = Connection::connect(env::var("DATABASE_URL").expect("Please set DATABASE_URL to the postgres database"),TlsMode::None).expect("Failed to connect to db!"); // TODO: Use an env var for the db url
    // TODO: Gracefully handle a lack of db!

    let mut client = Client::new(&token, Handler::new()).unwrap();

    {
        client.data.lock().insert::<DbKey>(Arc::new(Mutex::new(conn)));
    }

    // So for the hackmud chat feature, some kind of feature where you can define what users you
    // want to listen for, and it'll report back to you? It can also set up an automatic reminder
    // to reset your token

    if let Err(why) = client.start() {
        println!("Client error: {:?}", why);
    }
}
