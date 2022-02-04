// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(rust_2018_idioms)]
#![deny(clippy::perf)]
#![allow(
    clippy::complexity,
    clippy::type_complexity,
    clippy::new_without_default,
    clippy::upper_case_acronyms
)]
#![recursion_limit = "256"]

#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate counted_array;
#[cfg(feature = "jsonwebtoken")]
use jsonwebtoken as jwt;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

// To get macros in scope, this has to be first.
#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
pub mod errors;

#[cfg(feature = "azure")]
mod azure;
mod cache;
mod client;
mod cmdline;
mod commands;
mod compiler;
pub mod config;
pub mod coordinator;
pub mod dist;
mod jobserver;
pub mod lru_disk_cache;
mod mock_command;
mod protocol;
#[doc(hidden)]
pub mod util;

use std::env;

pub fn main() {
    init_logging();
    std::process::exit(match cmdline::parse() {
        Ok(cmd) => match commands::run_command(cmd) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cachepot: error: {}", e);
                for e in e.chain().skip(1) {
                    eprintln!("cachepot: caused by: {}", e);
                }
                2
            }
        },
        Err(e) => {
            println!("cachepot: {}", e);
            for e in e.chain().skip(1) {
                println!("cachepot: caused by: {}", e);
            }
            println!();
            1
        }
    });
}

pub fn init_logging() {
    const LOGGING_ENV: &str = "CACHEPOT_LOG";

    use env_logger::fmt::{Color, Style};
    use log::Level;
    use std::io::Write;

    /// The available service type that cachepot can run as.
    #[derive(Copy, Clone)]
    enum Kind {
        /// A service that connects a coordinator and a remote worker to execute
        /// a remote build.
        DistScheduler,
        /// A service that's used to directly perform remote sandbox compilation
        DistWorker,
        /// A background service used by the cachepot compilation wrapper (client)
        /// to either re-use local compilation cache or schedule a remote
        /// compilation via a remote scheduler
        Coordinator,
        /// A wrapper that masquerades as a compiler but spawns (or talks to) a
        /// coordinator to perform the actual compilation locally or offload it
        /// to a distributed cluster (in both cases we can re-use cached artifacts)
        Client,
    }

    impl std::fmt::Display for Kind {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}",
                match self {
                    Kind::DistScheduler => "dist scheduler",
                    Kind::DistWorker => "dist worker",
                    Kind::Coordinator => "coordinator",
                    Kind::Client => "client",
                }
            )
        }
    }

    let start_coordinator = env::var("CACHEPOT_START_COORDINATOR").is_ok()
        || env::args_os().any(|a| a == "--start-coordinator");

    // TODO: That's a rough heuristic - share detection logic from cmdline.rs
    let kind = match (std::env::args().nth(1).as_deref(), start_coordinator) {
        (Some("scheduler"), _) => Kind::DistScheduler,
        (Some("worker"), _) => Kind::DistWorker,
        (_, true) => Kind::Coordinator,
        _ => Kind::Client,
    };

    let color_for_kind = |kind| match kind {
        Kind::DistScheduler => Color::Yellow,
        Kind::DistWorker => Color::Cyan,
        Kind::Coordinator => Color::Blue,
        Kind::Client => Color::Green,
    };

    let default_level_style = |mut level_style: Style, level: Level| {
        match level {
            Level::Trace => level_style.set_color(Color::Cyan),
            Level::Debug => level_style.set_color(Color::Blue),
            Level::Info => level_style.set_color(Color::Green),
            Level::Warn => level_style.set_color(Color::Yellow),
            Level::Error => level_style.set_color(Color::Red).set_bold(true),
        };
        level_style
    };

    if env::var(LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(LOGGING_ENV);
        // That's mostly what env_logger does by default but we also attach the
        // PID and kind of the cachepot executable due to its multi-process nature
        builder.format(move |f, record| {
            write!(
                f,
                "{}",
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
            )?;
            let style = default_level_style(f.style(), record.level());
            write!(f, " {:<5}", style.value(record.level()))?;
            write!(f, " [PID {}]", std::process::id())?;
            let mut style = f.style();
            style.set_color(color_for_kind(kind));
            write!(f, " {:>14}", style.value(kind))?;
            writeln!(f, " {}", record.args())
        });
        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initalize logging: {:?}", e),
        }
    }
}
