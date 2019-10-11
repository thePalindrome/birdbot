extern crate reqwest;
extern crate serenity;
extern crate chrono;
extern crate regex;
extern crate serde;
extern crate env_logger;
extern crate typemap;
extern crate num_bigint;
extern crate openweather;

#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
#[macro_use] extern crate postgres_derive;
#[macro_use] extern crate postgres;


mod hm;
mod skullgirls;

static mut THREADED: bool = false;

use serenity::Client;
use serenity::prelude::*;
use serenity::model::prelude::*;

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

use num_bigint::BigUint;

use openweather::LocationSpecifier;


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
    owm_key: String,
}

struct BirdbotUser {
    id: i64,
	#[allow(dead_code)]
    hm_tok: Option<String>,
	#[allow(dead_code)]
    hm_usernames: Option<Vec<String>>,
    is_admin: bool
}

#[derive(Debug, FromSql, ToSql)]
#[postgres(name = "Record")] 
struct MemberId {
    uid: i64,
    gid: i64
}

#[derive(Debug, FromSql, ToSql, Clone)]
#[postgres(name = "permission_override")]
struct Override {
    channel: i64,
    allow: i64,
    deny: i64
}

impl Config {
    fn flush(&self) {
        let str = serde_json::to_string_pretty(self).unwrap();
        let mut f = File::create("/etc/birdbot").unwrap(); // TODO: Maybe make sure nobody touched it before we wipe it?
        f.write_all(str.as_bytes()).unwrap();
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
                        owm_key: env::var("OWM_KEY").expect("Please set OWM_KEY to your openweathermap appid"),
                    }
                }
        };
        Self {
config: Arc::new(Mutex::new(config)),
        }
    }
}

fn paying_attention(ctx: &Context, msg: &Message) -> bool{
    // Check if I'm in a DM, being mentioned, or otherwise has been requested
    if msg.is_own(ctx) {
        return false; // Don't react to my own messages, please
    }
    /*if msg.content.contains("birdbot") { // TODO: Allow disabling just using my name
      return true;
      }*/
    if msg.mentions.iter().any( |x| { x.id == ctx.cache.read().user.id } ) {
        return true;
    }
    if msg.is_private() {
        return true;
    }
    false
}

impl EventHandler for Handler {
    fn guild_ban_addition(&self, ctx: Context, guild_id: GuildId, user: User) {
        let data = ctx.data.read();
        let conn = data.get::<DbKey>().expect("Failed to read db handle").lock();
        if let Err(e) = conn.execute("DELETE FROM members WHERE id = (CAST($2 AS BIGINT) , CAST($3 AS BIGINT) )",
			&[&(*user.id.as_u64() as i64), &(*guild_id.as_u64() as i64)]) {
				error!("Unable to remove user {} from guild {} after banning: {}",user.id,guild_id,e);
		}
    }
    fn guild_member_update(&self, ctx: Context, _old: Option<Member>, member: Member) {
        println!("Updating user {}", member.user_id().as_u64());
        let data = ctx.data.read();
        let conn = data.get::<DbKey>().expect("Failed to read db handle").lock();
        let db_role_list: Vec<i64> = member.roles.iter().map(|x| *x.as_u64() as i64).collect();
        conn.execute("INSERT INTO members(id,roles,overrides) VALUES (
            (CAST($2 AS BIGINT) , CAST($3 AS BIGINT) ),
            $1,
            $4
            ) ON CONFLICT (id) DO UPDATE SET roles = $1",
                    &[&db_role_list, &(*member.user_id().as_u64() as i64), &(*member.guild_id.as_u64() as i64), &mut Vec::<Override>::new() ]).unwrap();

    }
    fn guild_member_addition(&self, ctx: Context, guild_id: GuildId, mut member: Member) {
        let data = ctx.data.read();
        let conn = data.get::<DbKey>().expect("Failed to read db handle").lock();
        let user_id = member.user_id();
        let member_id = MemberId {
            uid: *user_id.as_u64() as i64,
            gid: *guild_id.as_u64() as i64
        };
        // TODO: Figure out why the ToSql side of things is just so freaking broken.
        let rows = conn.query("SELECT * FROM members WHERE id = ( CAST($1 AS BIGINT) , CAST($2 AS BIGINT) )", &[&member_id.uid, &member_id.gid]).unwrap(); // TODO: prepare this query for extra speed
        if !rows.is_empty() {
            let row = rows.get(0);
            let roles: Vec<i64> = row.get("roles");
            let overrides: Vec<Override> = row.get("overrides");
            if !roles.is_empty() {
                if let Err(e) = member.add_roles(&ctx, &roles.into_iter().map(|e| RoleId(e as u64)).collect::<Vec<_>>()) {
					error!("Unable to add roles to {}: {}", member.display_name(), e);
				}
            }
            for perm in overrides.iter() {
                if let Err(e) = ChannelId(perm.channel as u64).create_permission(&ctx, &PermissionOverwrite {
                    allow: Permissions::from_bits_truncate(perm.allow as u64),
                    deny: Permissions::from_bits_truncate(perm.deny as u64),
                    kind: PermissionOverwriteType::Member(user_id),
                }) {
					error!("Unable to set permissions for channel {} for user {}: {}", perm.channel, user_id, e);
				}
            }
            /*if motd {
                member.user.direct_message(&ctx, |m| {
                    m.content(motd)
                });
            }*/
        }
    }
    fn message(&self, ctx: Context, msg: Message) {
        if paying_attention(&ctx,&msg) {
            lazy_static! {
                static ref REMIND_REGEX: Regex = Regex::new(r"(?i)remind me (.*?) in (\d* \w*)( every (\d* \w*))?").unwrap();
                static ref FACTOR_REGEX: Regex = Regex::new(r"(?i)factor (.\d*)").unwrap();
                static ref SKULLGIRLS_REGEX: Regex = Regex::new(r"(?i)play a game with (.*) (against|vs.|vs) (.*)").unwrap();
                static ref WEATHER_REGEX: Regex = Regex::new(r"(?i)what('s| is) the weather in (.*)\?").unwrap();
            }

            let user = {
                    let data = ctx.data.read();
                    let conn = data.get::<DbKey>().expect("AAAA").lock(); // TODO: Prepare this query for extra speed
                    let mut rows = conn.query("SELECT * FROM users WHERE id = $1",  &[&(*msg.author.id.as_u64() as i64)]).unwrap();
                    let row = { if rows.is_empty() {
                            conn.execute("INSERT INTO users (id) VALUES ($1)", &[&(*msg.author.id.as_u64() as i64)]).unwrap();
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

            if SKULLGIRLS_REGEX.is_match(&command_list) { // Play a round
                let list_copy = &command_list.clone();
                let captures = SKULLGIRLS_REGEX.captures(list_copy).unwrap(); // Safe because is_match

                let player_1_str = str::replace(captures.get(1).unwrap().as_str(), ",", "");
                let player_2_str = str::replace(captures.get(3).unwrap().as_str(), ",", "");

                for _player in player_1_str.split(" ") {
                }

                for _player in player_2_str.split(" ") {
                } // Alright, now we have our players

                if let Err(e) = msg.reply(&ctx,&skullgirls::simulate_fight(vec!(player_1_str),vec!(player_2_str))) {
					error!("Unable to reply to {} to simulate a fight: {}",&msg.author.name, e);
				};
            }

            if WEATHER_REGEX.is_match(&command_list) { // Weather :D
                let list_copy = &command_list.clone();
                let captures = WEATHER_REGEX.captures(list_copy).unwrap();
                let zip = captures.get(2).unwrap().as_str();
                let loc = LocationSpecifier::CityAndCountryName{city: zip, country: ""};
                match openweather::get_5_day_forecast(loc, &self.config.lock().owm_key) {
                    Ok(weather) => {
                        println!("got weather");
                        let now = &weather.list[0];
                        if let Err(e) = msg.channel_id.send_message(&ctx, |m| {
                            m.embed(|e| {
                                e.title(format!("Weather for {}", weather.city.name))
                                    .image(format!("https://openweathermap.org/img/wn/{}@2x.png",now.weather[0].icon))
                                    .description(format!("{}°F {}%💧 {}%☁️  {}💨",(now.main.temp - 273.15) as f32 * (9/5) as f32 + 32.0, now.main.humidity,now.clouds.all, now.wind.speed));
                                for w in weather.list.iter().step_by(8).skip(1) {
                                    e.field(w.dt_txt.clone(), format!("{}  {}°F", w.weather[0].description, (w.main.temp - 273.15) as f32 * (9/5) as f32 + 32.0),false);
                                }
                                e
                            });

                            m
                        }) {
							error!("Unable to embed weather info: {}", e);
						}
                    },
                    Err(err) => { error!("{:#?}",err); },
                };
                command_list = command_list.replace(captures.get(0).unwrap().as_str(),"");
            }

            if REMIND_REGEX.is_match(&command_list) { // reminder handling
                let list_copy = &command_list.clone();
                let reminder = REMIND_REGEX.captures(list_copy).unwrap(); // Safe because I used is_match

                let remind_text = reminder.get(1).unwrap().as_str();
                let time_delay: Vec<&str> = reminder.get(2).unwrap().as_str().split(' ').collect();

                if time_delay.len() != 2 {
                    if let Err(e) = msg.reply(&ctx,"Unable to parse time to remind.") {
						error!("Unable to inform {} that I was unable to parse their reminder: {}",&msg.author.name, e);
					}
                }

                if let Ok(num) = time_delay[0].parse::<f64>() {
                    let sec_multi: f64 = match time_delay[1].to_lowercase().as_str() {
                            "seconds" => 1.0,
                            "secs" => 1.0,
                            "minutes" => 60.0,
                            "minute" => 60.0,
                            "hours" => 3600.0,
                            "hour" => 3600.0,
                            "days" => 86_400.0,
                            "day" => 86_400.0,
                            "weeks" => 604_800.0,
                            "week" => 604_800.0,
                            "months" => 2_419_200.0,
                            "month" => 2_419_200.0,
                            "years" => 31_449_600.0,
                            "year" => 31_449_600.0,
                            _ => { if let Err(e) = msg.reply(&ctx,"Invalid measurement of time") {
									error!("Unable to reply to {} regarding an invalid measurment of time: {}", &msg.author.name, e);
								};
								0.0},
                    };
                    if sec_multi != 0.0 {
                        let remind_time = Utc::now() + chrono::Duration::seconds( (num * sec_multi).floor() as i64 );
                        if let Err(e) = msg.reply(&ctx,&format!("Ok, I will remind you {} around {}.",remind_text,remind_time.format("%a %b %d %Y %T UTC"))) {
							error!("Unable to inform {} about their newly set reminder: {}", &msg.author.name, e); // Should I not push the reminder?
						}
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
if FACTOR_REGEX.is_match(&command_list) {
    if let Some(mut composite) = BigUint::parse_bytes(FACTOR_REGEX.captures(&command_list).unwrap().get(1).unwrap().as_str().as_bytes(), 10) {
        if composite > BigUint::from(std::u64::MAX) {
            if let Err(e) = msg.reply(&ctx, "What do you think I am, a crypto breaker?") {
				error!("Unable to refuse service to {}: {}", &msg.author.name, e);
			}
        } else {
        debug!("Factoring {}",composite);
        if composite == BigUint::from(1u64) || composite == BigUint::from(0u64)  {
            if let Err(e) = msg.reply(&ctx,"That's... not how this works.") {
				error!("Unable to sass the *heck* out of {}: {}", &msg.author.name, e);
			}
        } else {
        let mut factors: Vec<BigUint> = Vec::new();
        while &composite % 2u64 == BigUint::from(0u64) {
            composite /= 2u64;
            factors.push(BigUint::from(2u64));
        }
        let mut f: BigUint = BigUint::from(3u64);
        while &f * &f <= composite {
            if &composite % &f == BigUint::from(0u64) {
                factors.push(f.clone());
                composite /= &f;
            } else {
                f += BigUint::from(2u64);
            }
        }
        if composite != BigUint::from(1u64) { 
            factors.push(composite); 
        }
        let mut reply: String = "`".to_string();
        if factors.len() > 1 {
            let mut cur_factor: &BigUint = factors.first().unwrap();
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
            } else {
                reply.push_str(&format!(" {} *", cur_factor));
            }
            let length = reply.len();
            reply.truncate(length-2);
            reply.push('`');
        } else {
            reply = format!("`{} is a prime number`",factors.first().unwrap());
        }
        if let Err(e) = msg.reply(&ctx,&reply) {
			error!("Unable to reply to {} with factor response: {}", &msg.author.name, e);
		}
        } }
    } else if let Err(e) = msg.reply(&ctx,"Unable to parse factor") {
		error!("Unable to reply to {} with \"Unable to parse factor\": {}", &msg.author.name, e);
    }
    command_list = command_list.replace(FACTOR_REGEX.captures(&command_list).unwrap().get(0).unwrap().as_str(),"");
}

if command_list.contains("help") {
    if let Err(e) = msg.reply(&ctx,"Current commands: `remind me X in Y time_units`\n`factor <u64>`") {
		error!("Unable to reply to {} with the help message: {}", &msg.author.name, e);
	}
}

if user.is_admin  { 
    if command_list.contains("away") {
        ctx.idle();
    } else if command_list.starts_with("/who ") {
        let a: Vec<&str> = command_list.split(' ').collect();
        if a.len() != 2 {
            let _ = msg.author.direct_message(&ctx,|m| m.content("/who <UID>"));
            return;
        }
        let uid: u64 = match a[1].parse() {
            Ok(x) => x,
                Err(e) => {
                    let _ = msg.author
                        .direct_message(&ctx,|m| m.content(format!("Unable to format: {}", e)));
                    return;
                }
        };
        if let Err(e) = match UserId(uid).to_user(&ctx) {
				Ok(x) => msg.reply(&ctx,&x.name),
				Err(x) => msg.reply(&ctx,&format!("{:?}", x))
			} {
			error!("Unable to reply with user info: {}", e);
		}
        return;
    } else if command_list.contains("plzdienow") {
        let _ = &ctx.shard.shutdown_clean();
        return;
    } else if command_list.starts_with("/auth ") {
        let a: Vec<&str> = command_list.split(' ').collect();
        if a.len() != 2 {
            msg.author
                .direct_message(&ctx,|m| m.content("Try `/auth <hackmud_pass>`"))
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
                        .direct_message(&ctx,|m| m.content(format!("failed to parse: {}", e)));
                    return;
                }
        };
        if raw["chat_token"].is_string() {
            let tok = String::from_str(raw["chat_token"].as_str().unwrap()).unwrap();

                let data = &ctx.data.read();
                // TODO: Ensure that a username list is configured!
                {
                    let conn = data.get::<DbKey>().expect("Unable to get DB!").lock();
                    if let Ok(_x) = conn.execute("UPDATE users SET hm_tok=$1 WHERE id=$2", &[&tok, &user.id]) {
                        let _ = msg.react(&ctx,"✅");
                    }
                }
            
        } else if let Err(e) = msg.author.direct_message(&ctx,|m| m.content(format!("Error: {}",raw))) {
			error!("Unable to DM user {} regarding failure of hackmud reauthorization: {}", &msg.author.name, e);
        }
    }
    else if command_list.contains("/roles") {
        let member = msg.member(&ctx).unwrap();
        self.guild_member_addition(ctx, msg.guild_id.unwrap(), member);
    }
    else if command_list.contains("/hardscan") { // TOOD: Stubbed so I can hurry and get this uploaded

        use serenity::model::prelude::PermissionOverwriteType::Member;
        use std::collections::HashMap;

        let data = ctx.data.read();
        let conn = data.get::<DbKey>().expect("Failed to read db handle").lock();
        let guild_id = msg.guild_id.expect("No guild_id?");
        let mut updates = 0;
        let mut perm_map: HashMap<serenity::model::id::UserId, Vec<Override>> = HashMap::new();

        for (channel_id, channel) in guild_id.channels(&ctx).unwrap() {
            for perm in channel.permission_overwrites {
                if let Member(uid) = perm.kind {
					let overrides = {
						let mut override_vec = vec!( Override { channel: *channel_id.as_u64() as i64, allow: perm.allow.bits as i64, deny: perm.deny.bits as i64 } );
						if let Some(overrides_old) = perm_map.get_mut(&uid) {
							override_vec.append(overrides_old);
						}
						override_vec
					};
					perm_map.insert(uid, overrides.to_vec());
                }
            }
        }
        let cached_guild = ctx.cache.read().guild(guild_id).unwrap();
        let guild = cached_guild.read();
        let stmnt = conn.prepare("
            INSERT INTO members(id,roles,overrides) VALUES (
            (CAST($2 AS BIGINT) , CAST($3 AS BIGINT) ),
            $1,
            $4
            ) ON CONFLICT (id) DO UPDATE SET roles = $1").unwrap();
        for member in guild.members.values() { // Then iterate over each user, picking up their roles and inserting them into the db
            let db_role_list: Vec<i64> = member.roles.iter().map(|x| *x.as_u64() as i64).collect();
            let overrides = if perm_map.get(&member.user_id()).is_some() {
                    perm_map.get(&member.user_id()).unwrap().to_vec()
                } else {
                    Vec::<Override>::new()
                };
                updates += stmnt.execute(
                &[&db_role_list, &(*member.user_id().as_u64() as i64), &(*guild_id.as_u64() as i64), &overrides ]).unwrap();
        }
        let _ = msg.reply(&ctx,format!("{} users registered", updates));
    }
}
}
}

fn ready(&self, ctx: Context, _: Ready) {
    let client = reqwest::Client::new();
    let local_safe_var = unsafe { THREADED };
    if !local_safe_var {
        ctx.set_activity(Activity::listening("the conversation"));
        unsafe {
            THREADED = true;
        }
        let config = Arc::clone(&self.config);
        let conn = Arc::clone(ctx.data.read().get::<DbKey>().expect("AAAA"));
        thread::spawn(move || {
                debug!("Timed thread started");
                let mut time = Utc::now().timestamp() - 31;
                loop {
                {
                let mut conf = config.lock();

                for hm_user in conn.lock().query("SELECT id, hm_tok, hm_usernames FROM users WHERE hm_tok IS NOT NULL", &[]).unwrap().iter() {
                    let uid: i64 = hm_user.get(0);
                    let user = UserId(uid as u64).to_user(&ctx).unwrap(); // TODO: Delete the hm_tok if this operation fails, since I can't contact them.
                    match hm::hm_loop(time, &client, hm_user.get(1), hm_user.get(2)) {
                        Ok(x) => {
                            for i in x {
                                let _ = user.direct_message(&ctx,|m| m.content(i));
                            }},
                        Err(e) => {let _ = user.direct_message(&ctx,|m| m.content(e));},
                    }
                }

                let cur_time = Utc::now();
                let mut expired_reminders: Vec<usize> = Vec::new();
                for (index, reminder) in conf.reminders.iter().enumerate() {
                    if reminder.reminder_time < cur_time {
                        let text = serenity::utils::content_safe(&ctx,&reminder.reminder_text, {&serenity::utils::ContentSafeOptions::default()});
                        match reminder.channel.to_channel(&ctx) {
                            Ok(thing) => {
                                    if let Err(e) = thing.id().say(&ctx,&format!("{} Don't forget {}", reminder.user.mention(), text)) {
                                        println!("Failed to send message to {} : {}", reminder.channel, e);
                                    }
                            },   
                            Err(e) => { 
                                if let Ok(dm) = reminder.user.create_dm_channel(&ctx) {
                                    let _ = dm.say(&ctx,&format!("{} Don't forget {}", reminder.user.mention(), reminder.reminder_text));
                                } else {
                                    println!("Failed to send DM to {} : {}", reminder.user.mention(), e);
                                }
                            }
                        }
                        expired_reminders.push(index);
                    }
                }

                for (offset, i) in expired_reminders.iter().enumerate() {
                    conf.reminders.remove(i - offset);
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
    

    debug!("DB connection established");

    let mut client = Client::new(&token, Handler::new()).unwrap();
    
    debug!("serenity Client started");

    {
        client.data.write().insert::<DbKey>(Arc::new(Mutex::new(conn)));
    }

    // So for the hackmud chat feature, some kind of feature where you can define what users you
    // want to listen for, and it'll report back to you? It can also set up an automatic reminder
    // to reset your token

    if let Err(why) = client.start() {
        println!("Client error: {:?}", why);
    }
    debug!("Pre-init complete");
}
