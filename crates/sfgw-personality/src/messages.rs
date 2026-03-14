// SPDX-License-Identifier: AGPL-3.0-or-later

//! Randomized error messages per personality and HTTP status / event type.
//!
//! Each personality defines its own set of messages. The active personality
//! is checked on every call, so switching mid-flight works instantly.

use rand::Rng;

use crate::Personality;

/// Pick a random message from a slice.
fn pick(msgs: &[&'static str]) -> &'static str {
    msgs[rand::thread_rng().gen_range(0..msgs.len())]
}

// ---------------------------------------------------------------------------
// 401 Unauthorized
// ---------------------------------------------------------------------------

/// Random 401 message in the active personality.
pub fn unauthorized() -> &'static str {
    pick(unauthorized_msgs(crate::active()))
}

fn unauthorized_msgs(p: Personality) -> &'static [&'static str] {
    match p {
        Personality::Kevin => &[
            "log dich ein junge!",
            "oh mann...",
            "wirklich?",
            "versuch noch ein paar mal",
            "netter versuch",
            "who are you?",
            "erstmal einloggen, dann reden wir",
            "denied.",
            "schon wieder du?",
            "nope.",
        ],
        Personality::Corporate => &[
            "authentication required",
            "please provide valid credentials",
            "access denied: invalid or missing token",
            "session expired, please log in again",
            "unauthorized request",
        ],
        Personality::Pirate => &[
            "ye be no crew of mine!",
            "show yer papers or walk the plank!",
            "no boarding pass, no entry, scallywag!",
            "arrr, who goes there?!",
            "the captain don't know ye!",
            "stowaways get thrown overboard!",
        ],
        Personality::Zen => &[
            "the gate remains closed to those who do not know the way",
            "identity is an illusion. yours especially.",
            "you seek access, but access does not seek you",
            "the lock does not yield to wishes",
            "first, know thyself. then, log in.",
        ],
        Personality::Bofh => &[
            "LUSER DETECTED",
            "your credentials were lost in a tragic boating accident",
            "I don't recognize you and I don't want to",
            "access denied. try again never.",
            "error: user not found in give-a-damn database",
            "your session was terminated for your own protection. and mine.",
        ],
        Personality::UnrealTournament => &[
            "DENIED!",
            "you be dead!",
            "get out of my way!",
            "anyone else want some?!",
            "not even close!",
            "try turning the safety off",
        ],
        Personality::GamingLegends => &[
            "YOU SHALL NOT PASS!",
            "hey! listen! ...you're not logged in.",
            "it's a-me, access denied!",
            "the cake is a lie. and so is your session.",
            "would you kindly... authenticate?",
            "I used to be an unauthenticated user like you, then I took a 401 to the knee.",
            "a man chooses, a slave obeys. you? you log in.",
        ],
    }
}

// ---------------------------------------------------------------------------
// 429 Rate Limited
// ---------------------------------------------------------------------------

/// Random 429 message in the active personality.
pub fn rate_limited() -> &'static str {
    pick(rate_limited_msgs(crate::active()))
}

fn rate_limited_msgs(p: Personality) -> &'static [&'static str] {
    match p {
        Personality::Kevin => &[
            "verkackt",
            "das war zu viel",
            "jo, machen wir mal eine kleine pause wa?",
            "langsam jansen, langsam!",
            "chill mal",
            "zu viele anfragen, digga",
            "easy tiger",
            "du schon wieder...",
        ],
        Personality::Corporate => &[
            "rate limit exceeded",
            "too many requests, please wait",
            "request throttled",
            "please reduce request frequency",
        ],
        Personality::Pirate => &[
            "ye be firing too many cannons!",
            "the ship can't take much more, captain!",
            "slow down or ye'll capsize!",
            "even pirates need rest, matey!",
            "the rum is flowing too fast!",
        ],
        Personality::Zen => &[
            "patience, grasshopper",
            "the river does not rush to the sea",
            "stillness is the path to clarity",
            "you pour tea too fast and it spills",
            "breathe. wait. try again.",
        ],
        Personality::Bofh => &[
            "you're DDoS-ing my patience",
            "I'm throttling you harder than your ISP",
            "rate limited. deal with it.",
            "slow down before I null-route you",
            "your requests have been placed in the circular file",
        ],
        Personality::UnrealTournament => &[
            "IMPRESSIVE... but slow down!",
            "COMBO BREAKER!",
            "you're on fire! ...literally. cooling down.",
            "MULTI KILL denied — too fast!",
            "headshot limit reached!",
        ],
        Personality::GamingLegends => &[
            "LEEEEROOOYYYY JENKIIIIINS! *port off*",
            "you have died of dysentery. also, rate limited.",
            "all your requests are belong to /dev/null",
            "do a barrel roll! ...but slower.",
            "snake? SNAKE?! SNAAAAKE!! ...too many requests.",
            "pause menu not available in online mode. wait.",
        ],
    }
}

// ---------------------------------------------------------------------------
// 403 Forbidden
// ---------------------------------------------------------------------------

/// Random 403 message in the active personality.
pub fn forbidden() -> &'static str {
    pick(forbidden_msgs(crate::active()))
}

fn forbidden_msgs(p: Personality) -> &'static [&'static str] {
    match p {
        Personality::Kevin => &[
            "nicht dein revier",
            "nein.",
            "da kommst du nicht rein",
            "schoen waers",
            "access denied, punkt.",
        ],
        Personality::Corporate => &[
            "forbidden",
            "insufficient permissions",
            "you do not have access to this resource",
            "authorization failed",
        ],
        Personality::Pirate => &[
            "this treasure ain't yers!",
            "ye lack the rank, sailor!",
            "the captain's quarters are off limits!",
            "hands off the loot!",
        ],
        Personality::Zen => &[
            "this path is not yours to walk",
            "the door opens only for those who belong",
            "desire without permission is suffering",
            "you may look, but not touch",
        ],
        Personality::Bofh => &[
            "you don't have the clearance, and you never will",
            "forbidden. your access level is: peasant",
            "that's above your pay grade. way above.",
            "nice try, but I saw what you did last Tuesday",
        ],
        Personality::UnrealTournament => &[
            "you can't go there!",
            "ACCESS DENIED",
            "wrong team, buddy!",
            "flag defended!",
            "not on my watch!",
        ],
        Personality::GamingLegends => &[
            "it's dangerous to go alone — so don't.",
            "you are not prepared!",
            "the door is locked. you need the admin key.",
            "access denied. git gud.",
            "this is a restricted area. no continues.",
            "you lack the required clearance level. insert coin.",
        ],
    }
}

// ---------------------------------------------------------------------------
// 404 Not Found
// ---------------------------------------------------------------------------

/// Random 404 message in the active personality.
pub fn not_found() -> &'static str {
    pick(not_found_msgs(crate::active()))
}

fn not_found_msgs(p: Personality) -> &'static [&'static str] {
    match p {
        Personality::Kevin => &[
            "da ist nix",
            "falsche tuer",
            "404 - hier gibts nix zu sehen",
            "verirrt?",
            "lost.",
        ],
        Personality::Corporate => &[
            "resource not found",
            "the requested endpoint does not exist",
            "404 not found",
            "no resource at this location",
        ],
        Personality::Pirate => &[
            "there be nothing here, matey!",
            "X marks the spot... but not this spot!",
            "ye sailed to the wrong island!",
            "the treasure map lied!",
            "lost at sea!",
        ],
        Personality::Zen => &[
            "what you seek does not exist. perhaps it never did.",
            "emptiness is also an answer",
            "the void stares back",
            "nothing here. and nothing is everything.",
        ],
        Personality::Bofh => &[
            "it's not here. I moved it. good luck.",
            "404: I deleted it and I'd do it again",
            "that file was a security risk. you're welcome.",
            "not found. have you tried looking somewhere else? like, anywhere else?",
        ],
        Personality::UnrealTournament => &[
            "LOST!",
            "wrong map, noob!",
            "that level doesn't exist!",
            "you fell off the map!",
            "out of bounds!",
        ],
        Personality::GamingLegends => &[
            "the princess is in another castle.",
            "ERROR 404: this is not the page you are looking for.",
            "you are in a maze of twisty little passages, all alike. none lead here.",
            "missingno.",
            "secret area not found. try bombing every wall.",
            "this world doesn't exist. select another save file.",
        ],
    }
}

// ---------------------------------------------------------------------------
// IDS/IPS Blocked
// ---------------------------------------------------------------------------

/// IDS/IPS block message in the active personality.
pub fn ids_blocked() -> &'static str {
    pick(ids_blocked_msgs(crate::active()))
}

fn ids_blocked_msgs(p: Personality) -> &'static [&'static str] {
    match p {
        Personality::Kevin => &[
            "geh dich ficken - bye ;-)",
            "go fuck yourself - bye ;-)",
            "tschuess, werd dich nicht vermissen",
            "banned. war schoen mit dir. nicht.",
            "port off. ciao.",
        ],
        Personality::Corporate => &[
            "your connection has been terminated due to policy violation",
            "intrusion detected: connection blocked",
            "security event: access revoked",
            "blocked by intrusion prevention system",
        ],
        Personality::Pirate => &[
            "to Davy Jones' locker with ye!",
            "ye've been keelhauled!",
            "FIRE THE CANNONS! *boom*",
            "walk the plank, bilge rat!",
            "yer ship has been sunk!",
        ],
        Personality::Zen => &[
            "your journey ends here. reflect on your choices.",
            "the firewall is the wall. you are not the fire.",
            "you came seeking. you leave with nothing.",
            "silence falls. your packets dissolve into nothingness.",
        ],
        Personality::Bofh => &[
            "BANNED. your IP has been forwarded to people who care even less than I do.",
            "connection terminated with extreme prejudice",
            "I'm not just blocking you. I'm enjoying it.",
            "your packets have been recycled into something useful. unlike you.",
            "rm -rf /your/access",
        ],
        Personality::UnrealTournament => &[
            "GODLIKE! ...but not you. you're banned.",
            "FATALITY!",
            "GAME OVER!",
            "you have been ELIMINATED!",
            "FLAWLESS VICTORY! ...for the firewall.",
            "HUMILIATION!",
        ],
        Personality::GamingLegends => &[
            "all your base are belong to us. bye ;-)",
            "FINISH HIM! ...connection terminated.",
            "WASTED.",
            "you died. respawn disabled.",
            "game over. continue? no.",
            "a winner is you! ...just kidding. banned.",
            "the firewall has spoken: fus ro DENIED!",
        ],
    }
}

// ---------------------------------------------------------------------------
// Honeypot
// ---------------------------------------------------------------------------

/// Random honeypot troll response in the active personality.
pub fn honeypot_response() -> &'static str {
    pick(honeypot_msgs(crate::active()))
}

fn honeypot_msgs(p: Personality) -> &'static [&'static str] {
    match p {
        Personality::Kevin => &[
            "haha erwischt",
            "was suchst du hier?",
            "netter versuch lol",
            "dein admin wurde benachrichtigt ;-)",
            "01100110 01110101 01100011 01101011 00100000 01101111 01100110 01100110",
            "tschuess",
            "du kommst hier nicht rein. aber danke fuer die IP.",
            "> scanning port 28082\n> finding: deez nuts",
            "ich bin eine teekanne, kein server.",
            "willkommen im honeypot. deine daten werden jetzt an /dev/null gesendet.",
        ],
        Personality::Corporate => &[
            "this service is monitored. your connection has been logged.",
            "unauthorized access attempt recorded.",
            "security team has been notified.",
            "this incident will be reported.",
        ],
        Personality::Pirate => &[
            "ye fell for the decoy treasure, fool!",
            "HAHA! the kraken has yer IP now!",
            "this be a trap, and ye walked right in!",
            "the parrot saw everything. SQUAWK!",
            "yer coordinates have been logged, landlubber!",
        ],
        Personality::Zen => &[
            "you found the trap. or did the trap find you?",
            "the honeypot is a mirror. what do you see?",
            "congratulations. you played yourself.",
            "the bee sees the honey. the honey sees the bee.",
        ],
        Personality::Bofh => &[
            "welcome to the honeypot. your data is now my data.",
            "thanks for the IP. added to the permanent ban list.",
            "lol. lmao even. get rekt.",
            "you just triggered 47 alerts. good luck with that.",
            "I'm not even mad. this is just sad.",
        ],
        Personality::UnrealTournament => &[
            "HEADSHOT! ...on yourself, by walking into a trap.",
            "FIRST BLOOD! welcome to the honeypot.",
            "you picked up: nothing. it was a trap.",
            "CAMPING DETECTED! ...wait, that's us. carry on.",
            "M-M-M-MONSTER FAIL!",
        ],
        Personality::GamingLegends => &[
            "it's a trap! — Admiral Ackbar approved this honeypot.",
            "you have discovered: a mimic! it was not a real server.",
            "you opened the chest. it was empty. also, logged.",
            "achievement unlocked: walked into obvious trap",
            "the companion cube would never scan random ports.",
            "you picked up: your own IP address. congratulations.",
        ],
    }
}
