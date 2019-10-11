#![allow(dead_code)]
#![allow(unused_variables)]
extern crate rand;

use self::rand::prelude::*;

enum MoveDirection { Foward, Backward, None }
enum BlockType { High, Low }
enum PlayerSlot { First, Second }

enum PlayerAction {
    Nothing,
    Move(MoveDirection), 
    Outtake(PlayerSlot), 
    Block(BlockType), 
    Combo,
    Switch(PlayerSlot), 
    Jump(MoveDirection),
    Grab,
    Blockbuster(u8), // ID of the blockbuster
    Taunt
}

pub fn simulate_fight(player_one: Vec<String>, player_two: Vec<String>) -> String {
    let announcer_pre = ["It's all in the mind!"];
    let announcer_start = ["Let's go!","Action!","Showtime!"];
    let announcer_finish = ["Player {} wins!"];
    let player_1 = &player_one[0]; // TODO: Add support for more than 1v1
    let player_2 = &player_two[0];

    let mut rng = thread_rng();

    let mut ret = String::new();
    ret.push_str(rng.choose(&announcer_pre).unwrap());
    ret.push_str(rng.choose(&announcer_pre).unwrap());

    /*let winner = 0;
    while winner == 0 {
        // Decide what p1 does, then p2
        // Simulate both events
        // apply and return result
    }*/

    ret
}
