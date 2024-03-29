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

use crate::errors::*;
use clap::{ArgEnum, ArgGroup, StructOpt};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use strum::{EnumVariantNames, VariantNames};

#[derive(Copy, Clone, EnumVariantNames, ArgEnum, StructOpt, Debug)]
#[strum(serialize_all = "kebab_case")]
pub enum StatsFormat {
    Text,
    Json,
}

impl std::str::FromStr for StatsFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        for variant in Self::value_variants() {
            if variant.to_possible_value().unwrap().matches(s, false) {
                return Ok(*variant);
            }
        }
        Err(format!("Invalid variant: {}", s))
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    rename_all = "kebab-case",
    trailing_var_arg = true,
    group = ArgGroup::new("flags"),
    after_help = concat!(
"Enabled features:\n",
"    S3:        ", cfg!(feature = "s3"), "\n",
"    Redis:     ", cfg!(feature = "redis"), "\n",
"    Memcached: ", cfg!(feature = "memcached"), "\n",
"    GCS:       ", cfg!(feature = "gcs"), "\n",
"    Azure:     ", cfg!(feature = "azure"), "\n")
)]
pub struct Command2 {
    /// authenticate for distributed compilation
    #[structopt(long, group = "flags")]
    dist_auth: bool,

    /// show status of the distributed compilation
    #[structopt(long, group = "flags")]
    dist_status: bool,

    /// zero statistics counters
    #[structopt(long, short, group = "flags")]
    zero_stats: bool,

    /// start background server
    #[structopt(long, group = "flags")]
    start_coordinator: bool,

    /// stop background server
    #[structopt(long, group = "flags")]
    stop_coordinator: bool,

    /// show cache statistics
    #[structopt(short, long, group = "flags")]
    show_stats: bool,

    /// clear the contents of the on-disk cache
    #[structopt(long, group = "flags")]
    clear_cache: bool,

    /// package toolchain for distributed compilation
    #[structopt(
        long,
        required = false,
        use_value_delimiter = true,
        value_delimiter = ' ',
        value_names = &["executable", "out"],
        takes_value = true,
        number_of_values = 2,
    )]
    package_toolchain: Vec<PathBuf>,

    #[structopt(long, hide = true, group = "flags", env = "CACHEPOT_START_COORDINATOR")]
    internal_start_coordinator: Option<String>,

    /// set output format of statistics
    #[structopt(long, default_value = "text", possible_values = StatsFormat::VARIANTS)]
    stats_format: StatsFormat,

    cmd: Vec<OsString>,
}

impl TryFrom<Command2> for Command {
    type Error = anyhow::Error;

    fn try_from(cmd: Command2) -> Result<Self> {
        if Some("1") == cmd.internal_start_coordinator.as_deref() {
            Ok(Command::InternalStartCoordinator)
        } else if cmd.show_stats {
            Ok(Command::ShowStats(cmd.stats_format))
        } else if cmd.dist_status {
            Ok(Command::DistStatus)
        } else if cmd.zero_stats {
            Ok(Command::ZeroStats)
        } else if cmd.start_coordinator {
            Ok(Command::StartCoordinator)
        } else if cmd.stop_coordinator {
            Ok(Command::StopCoordinator)
        } else if cmd.dist_auth {
            Ok(Command::DistAuth)
        } else if cmd.clear_cache {
            Ok(Command::ClearCache)
        } else if cmd.package_toolchain.len() == 2 {
            Ok(Command::PackageToolchain(
                cmd.package_toolchain[0].clone(),
                cmd.package_toolchain[1].clone(),
            ))
        } else {
            let Command2 { cmd, .. } = cmd;

            let mut cmd = cmd.into_iter();

            if let Some(exe) = cmd.next() {
                let cmdline = cmd.collect::<Vec<_>>();
                let mut env_vars = env::vars_os().collect::<Vec<_>>();

                // If we're running under rr, avoid the `LD_PRELOAD` bits, as it will
                // almost surely do the wrong thing, as the compiler gets executed
                // in a different process tree.
                //
                // FIXME: Maybe we should strip out `LD_PRELOAD` always?
                if env::var_os("RUNNING_UNDER_RR").is_some() {
                    env_vars.retain(|(k, _v)| k != "LD_PRELOAD" && k != "RUNNING_UNDER_RR");
                }

                let cwd = env::current_dir()
                    .context("cachepot: Couldn't determine current working directory")?;
                Ok(Command::Compile {
                    exe,
                    cmdline,
                    cwd,
                    env_vars,
                })
            } else {
                bail!("No compile command");
            }
        }
    }
}

pub enum Command {
    /// Show cache statistics and exit.
    ShowStats(StatsFormat),
    /// Run background server.
    InternalStartCoordinator,
    /// Start background coordinator as a subprocess.
    StartCoordinator,
    /// Stop background server.
    StopCoordinator,
    /// Zero cache statistics and exit.
    ZeroStats,
    /// Show the status of the distributed client.
    DistStatus,
    /// Perform a login to authenticate for distributed compilation.
    DistAuth,
    /// Package a toolchain for distributed compilation (executable, out)
    PackageToolchain(PathBuf, PathBuf),
    /// Run a compiler command.
    Compile {
        /// The binary to execute.
        exe: OsString,
        /// The commandline arguments to pass to `exe`.
        cmdline: Vec<OsString>,
        /// The directory in which to execute the command.
        cwd: PathBuf,
        /// The environment variables to use for execution.
        env_vars: Vec<(OsString, OsString)>,
    },
    /// Clear the cache of entries.
    ClearCache,
}

/// Parse the commandline into a `Command` to execute.
pub fn parse() -> Result<Command> {
    let a = Command2::parse();
    Ok(a.try_into()?)
}
