#![deny(clippy::perf)]
#![allow(clippy::complexity, clippy::new_without_default)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use anyhow::{bail, Context, Error, Result};
use async_trait::async_trait;
use cachepot::config::{
    scheduler as scheduler_config, worker, WorkerUrl, INSECURE_DIST_CLIENT_TOKEN,
};
use cachepot::dist::{
    self, AllocJobResult, AssignJobResult, BuilderIncoming, CompileCommand, HeartbeatWorkerResult,
    InputsReader, JobAlloc, JobAuthorizer, JobComplete, JobId, JobState, RunJobResult,
    SchedulerIncoming, SchedulerOutgoing, SchedulerStatusResult, SubmitToolchainResult, TcCache,
    Toolchain, ToolchainReader, UpdateJobStateResult, WorkerIncoming, WorkerNonce, WorkerOutgoing,
};
use cachepot::init_logging;
use cachepot::util::daemonize;
use jsonwebtoken as jwt;
use rand::{rngs::OsRng, RngCore};
use std::collections::{btree_map, BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use syslog::Facility;

mod build;
mod token_check;

pub const INSECURE_DIST_WORKER_TOKEN: &str = "dangerously_insecure_worker";

#[derive(clap::Parser)]
enum Command {
    #[clap(subcommand)]
    Auth(AuthSubcommand),
    Scheduler(SchedulerSubcommand),
    Worker(WorkerSubcommand),
}

#[derive(clap::StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct SchedulerSubcommand {
    /// Use the scheduler config file at PATH
    #[structopt(long, value_name = "PATH")]
    config: PathBuf,

    /// Log to the syslog with LEVEL
    #[structopt(long, value_name = "LEVEL", possible_values = LOG_LEVELS)]
    syslog: Option<String>,
}

#[derive(clap::StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct WorkerSubcommand {
    /// Use the worker config file at PATH
    #[structopt(long, value_name = "PATH")]
    config: PathBuf,

    /// Log to the syslog with LEVEL
    #[structopt(long, value_name = "LEVEL", possible_values = LOG_LEVELS)]
    syslog: Option<String>,
}

#[derive(clap::StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct GenerateSharedToken {
    /// Use the specified number of bits for randomness
    #[structopt(long, default_value = "256")]
    bits: usize,
}

#[derive(clap::StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct GenerateJwtHS256WorkerToken {
    /// Use the key from the scheduler config file
    #[structopt(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Use specified key to create the token
    #[structopt(long, value_name = "KEY", required_unless_present = "config")]
    secret_key: Option<String>,

    /// Generate a key for the specified worker
    #[structopt(
        long,
        value_name = "WORKER_ADDR",
        required_unless_present = "secret_key"
    )]
    worker: WorkerUrl,
}

#[derive(clap::Subcommand)]
#[allow(clippy::enum_variant_names)]
enum AuthSubcommand {
    GenerateSharedToken(GenerateSharedToken),
    GenerateJwtHS256Key,
    GenerateJwtHS256WorkerToken(GenerateJwtHS256WorkerToken),
}

// Only supported on x86_64 Linux machines
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::StructOpt;
    use tokio::select;
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    init_logging();

    let run_fut = async move {
        let cmd = Command::parse();
        match run(cmd).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cachepot-dist: error: {}", e);

                for e in e.chain().skip(1) {
                    eprintln!("cachepot-dist: caused by: {}", e);
                }
                2
            }
        }
    };

    // Whenever `docker` or `systemd` stop the service, the signals
    // have to be processed and the app has to perform a graceful stop.
    select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
        res = run_fut => {
            std::process::exit(res);
        },
    }

    Ok(())
}

/// These correspond to the values of `log::LevelFilter`.
const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

fn check_init_syslog(name: &str, level: &str) -> Result<()> {
    let level = log::LevelFilter::from_str(level)?;
    drop(syslog::init(Facility::LOG_DAEMON, level, Some(name)));
    Ok(())
}

fn create_worker_token(worker_url: WorkerUrl, auth_token: &str) -> String {
    format!("{} {}", worker_url, auth_token)
}

fn check_worker_token(worker_token: &str, auth_token: &str) -> Option<WorkerUrl> {
    let mut split = worker_token.splitn(2, |c| c == ' ');
    let worker_addr = split.next()?;
    match split.next() {
        Some(t) if t == auth_token => Some(WorkerUrl::from_str(worker_addr).ok()?),
        Some(_) | None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerJwt {
    worker_url: WorkerUrl,
}
fn create_jwt_worker_token(
    worker_url: WorkerUrl,
    header: &jwt::Header,
    key: &[u8],
) -> Result<String> {
    let key = jwt::EncodingKey::from_secret(key);
    jwt::encode(header, &WorkerJwt { worker_url }, &key).map_err(Into::into)
}
fn dangerous_insecure_extract_jwt_worker_token(worker_token: &str) -> Option<WorkerUrl> {
    jwt::dangerous_insecure_decode::<WorkerJwt>(worker_token)
        .map(|res| res.claims.worker_url)
        .ok()
}
fn check_jwt_worker_token(
    worker_token: &str,
    key: &[u8],
    validation: &jwt::Validation,
) -> Option<WorkerUrl> {
    let key = jwt::DecodingKey::from_secret(key);
    jwt::decode::<WorkerJwt>(worker_token, &key, validation)
        .map(|res| res.claims.worker_url)
        .ok()
}

async fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::GenerateJwtHS256Key) => {
            let num_bytes = 256 / 8;
            let mut bytes = vec![0; num_bytes];
            OsRng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::GenerateJwtHS256WorkerToken(
            GenerateJwtHS256WorkerToken {
                config,
                secret_key,
                worker,
            },
        )) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);

            let secret_key = if let Some(config_path) = config {
                if let Some(config) = scheduler_config::from_path(&config_path)? {
                    match config.worker_auth {
                        scheduler_config::WorkerAuth::JwtHS256 { secret_key } => secret_key,
                        scheduler_config::WorkerAuth::Insecure
                        | scheduler_config::WorkerAuth::Token { token: _ } => {
                            bail!("Scheduler not configured with JWT HS256")
                        }
                    }
                } else {
                    bail!("Could not read config");
                }
            } else {
                secret_key.expect("missing secret-key in parsed subcommand")
            };

            let secret_key = base64::decode_config(&secret_key, base64::URL_SAFE_NO_PAD)?;
            let token = create_jwt_worker_token(worker, &header, &secret_key)
                .context("Failed to create worker token")?;
            println!("{}", token);
            Ok(0)
        }
        Command::Auth(AuthSubcommand::GenerateSharedToken(GenerateSharedToken { bits })) => {
            let num_bytes = bits / 8;
            let mut bytes = vec![0; num_bytes];
            OsRng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD));
            Ok(0)
        }

        Command::Scheduler(SchedulerSubcommand { config, syslog }) => {
            let scheduler_config::Config {
                public_addr,
                client_auth,
                worker_auth,
            } = if let Some(config) = scheduler_config::from_path(&config)? {
                config
            } else {
                bail!("Could not load config!");
            };

            if let Some(syslog) = syslog {
                check_init_syslog("cachepot", &syslog)?;
            }

            let checker_coordinator_auth: Box<dyn dist::http::CoordinatorAuthCheck> =
                match client_auth {
                    scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                        INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                    )),
                    scheduler_config::ClientAuth::Token { token } => {
                        Box::new(token_check::EqCheck::new(token))
                    }
                    scheduler_config::ClientAuth::JwtValidate {
                        audience,
                        issuer,
                        jwks_url,
                    } => Box::new(
                        token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                            .await
                            .context("Failed to create a checker for valid JWTs")?,
                    ),
                    scheduler_config::ClientAuth::Mozilla { required_groups } => {
                        Box::new(token_check::MozillaCheck::new(required_groups))
                    }
                    scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => {
                        Box::new(token_check::ProxyTokenCheck::new(url, cache_secs))
                    }
                };

            let check_worker_auth: dist::http::WorkerAuthCheck = match worker_auth {
                scheduler_config::WorkerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE worker authentication");
                    let token = INSECURE_DIST_WORKER_TOKEN;
                    Arc::new(move |worker_token| check_worker_token(worker_token, token))
                }
                scheduler_config::WorkerAuth::Token { token } => {
                    Arc::new(move |worker_token| check_worker_token(worker_token, &token))
                }
                scheduler_config::WorkerAuth::JwtHS256 { secret_key } => {
                    let secret_key = base64::decode_config(&secret_key, base64::URL_SAFE_NO_PAD)
                        .context("Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let validation = jwt::Validation {
                        leeway: 0,
                        validate_exp: false,
                        validate_nbf: false,
                        aud: None,
                        iss: None,
                        sub: None,
                        algorithms: vec![jwt::Algorithm::HS256],
                    };
                    Arc::new(move |worker_token| {
                        check_jwt_worker_token(worker_token, &secret_key, &validation)
                    })
                }
            };

            daemonize()?;
            let scheduler = Scheduler::new();
            let http_scheduler = dist::http::Scheduler::new(
                public_addr.to_url().clone(),
                scheduler,
                checker_coordinator_auth,
                check_worker_auth,
            );
            void::unreachable(http_scheduler.start().await?);
        }

        Command::Worker(WorkerSubcommand { config, syslog }) => {
            let worker::Config {
                builder,
                cache_dir,
                public_addr,
                scheduler_url,
                scheduler_auth,
                toolchain_cache_size,
            } = if let Some(config) = worker::from_path(&config)? {
                config
            } else {
                bail!("Could not load config!");
            };

            if let Some(syslog) = syslog {
                check_init_syslog("cachepot-build-coordinator", &syslog)?;
            }

            let builder: Box<dyn dist::BuilderIncoming> = match builder {
                worker::BuilderType::Docker => {
                    Box::new(build::DockerBuilder::new().context("Docker builder failed to start")?)
                }
                worker::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                    driver,
                } => Box::new(
                    build::OverlayBuilder::new(bwrap_path, build_dir, driver)
                        .context("Overlay builder failed to start")?,
                ),
            };

            let worker_url = public_addr.clone();
            let scheduler_auth = match scheduler_auth {
                worker::SchedulerAuth::Insecure => {
                    warn!("Worker starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_worker_token(worker_url, INSECURE_DIST_WORKER_TOKEN)
                }
                worker::SchedulerAuth::Token { token } => create_worker_token(worker_url, &token),
                worker::SchedulerAuth::JwtToken { token } => {
                    let token_worker_url: WorkerUrl =
                        dangerous_insecure_extract_jwt_worker_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_worker_url != worker_url {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_worker_url,
                            worker_url
                        )
                    }
                    token
                }
            };

            let worker = Worker::new(builder, &cache_dir, toolchain_cache_size)
                .context("Failed to create cachepot server instance")?;
            let http_server = dist::http::Worker::new(
                public_addr.0.to_url().clone(),
                scheduler_url.to_url().clone(),
                scheduler_auth,
                worker,
            )
            .context("Failed to create cachepot HTTP server instance")?;
            void::unreachable(http_server.start().await?)
        }
    }
}

const MAX_PER_CORE_LOAD: f64 = 10f64;
const WORKER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct JobDetail {
    worker_url: WorkerUrl,
    state: JobState,
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    job_count: AtomicUsize,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,

    workers: Mutex<HashMap<WorkerUrl, WorkerDetails>>,
}

struct WorkerDetails {
    jobs_assigned: HashSet<JobId>,
    // Jobs assigned that haven't seen a state change. Can only be pending
    // or ready.
    jobs_unclaimed: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    num_cpus: usize,
    worker_nonce: WorkerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            job_count: AtomicUsize::new(0),
            jobs: Mutex::new(BTreeMap::new()),
            workers: Mutex::new(HashMap::new()),
        }
    }

    fn prune_workers(
        &self,
        workers: &mut MutexGuard<HashMap<WorkerUrl, WorkerDetails>>,
        jobs: &mut MutexGuard<BTreeMap<JobId, JobDetail>>,
    ) {
        let now = Instant::now();

        let mut dead_servers = Vec::new();

        for (worker_url, details) in workers.iter() {
            if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                dead_servers.push(worker_url.clone());
            }
        }

        for worker_url in dead_servers {
            warn!(
                "Worker {} appears to be dead, pruning it in the scheduler",
                worker_url
            );
            let worker_details = workers
                .remove(&worker_url)
                .expect("worker went missing from map");
            for job_id in worker_details.jobs_assigned {
                warn!(
                    "Non-terminated job {} was cleaned up in worker pruning",
                    job_id
                );
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!(
                        "Non-terminated job {} assignment originally failed.",
                        job_id
                    );
                }
            }
        }
    }
}

#[async_trait]
impl SchedulerIncoming for Scheduler {
    async fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
    ) -> Result<AllocJobResult> {
        let (job_id, worker_url, auth) = {
            // LOCKS
            let mut workers = self.workers.lock().unwrap();

            let res = {
                let mut best = None;
                let mut best_err = None;
                let mut best_load: f64 = MAX_PER_CORE_LOAD;
                let now = Instant::now();
                for (worker_url, details) in workers.iter_mut() {
                    let load = details.jobs_assigned.len() as f64 / details.num_cpus as f64;

                    if let Some(last_error) = details.last_error {
                        if load < MAX_PER_CORE_LOAD {
                            if now.duration_since(last_error) > WORKER_REMEMBER_ERROR_TIMEOUT {
                                details.last_error = None;
                            }
                            match best_err {
                                Some((
                                    _,
                                    &mut WorkerDetails {
                                        last_error: Some(best_last_err),
                                        ..
                                    },
                                )) => {
                                    if last_error < best_last_err {
                                        trace!(
                                            "Selected {:?}, its most recent error is {:?} ago",
                                            worker_url,
                                            now - last_error
                                        );
                                        best_err = Some((worker_url.clone(), details));
                                    }
                                }
                                _ => {
                                    trace!(
                                        "Selected {:?}, its most recent error is {:?} ago",
                                        worker_url,
                                        now - last_error
                                    );
                                    best_err = Some((worker_url.clone(), details));
                                }
                            }
                        }
                    } else if load < best_load {
                        best = Some((worker_url.clone(), details));
                        trace!("Selected {:?} as the worker with the best load", worker_url);
                        best_load = load;
                        if load == 0f64 {
                            break;
                        }
                    }
                }

                // Assign the job to our best choice
                if let Some((worker_url, worker_details)) = best.or(best_err) {
                    let job_count = self.job_count.fetch_add(1, Ordering::SeqCst) as u64;
                    let job_id = JobId(job_count);
                    assert!(worker_details.jobs_assigned.insert(job_id));
                    assert!(worker_details
                        .jobs_unclaimed
                        .insert(job_id, Instant::now())
                        .is_none());

                    info!(
                        "Job {} created and will be assigned to server {}",
                        job_id, &worker_url
                    );
                    let auth = worker_details
                        .job_authorizer
                        .generate_token(job_id)
                        .map_err(Error::from)
                        .context("Could not create an auth token for this job")?;
                    Some((job_id, worker_url, auth))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let msg = format!(
                    "Insufficient capacity across {} available servers",
                    workers.len()
                );
                return Ok(AllocJobResult::Fail { msg });
            }
        };
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(worker_url.clone(), job_id, tc, auth.clone())
            .await
            .with_context(|| {
                // LOCKS
                let mut workers = self.workers.lock().unwrap();
                if let Some(entry) = workers.get_mut(&worker_url) {
                    entry.last_error = Some(Instant::now());
                    entry.jobs_unclaimed.remove(&job_id);
                    if !entry.jobs_assigned.remove(&job_id) {
                        "assign job failed and job not known to the worker"
                    } else {
                        "assign job failed, job un-assigned from the worker"
                    }
                } else {
                    "assign job failed and worker not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();

            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
            assert!(jobs
                .insert(
                    job_id,
                    JobDetail {
                        worker_url: worker_url.clone(),
                        state
                    }
                )
                .is_none());
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            worker_url: worker_url.clone(),
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }

    fn handle_heartbeat_worker(
        &self,
        worker_url: WorkerUrl,
        worker_nonce: WorkerNonce,
        num_cpus: usize,
        job_authorizer: Box<dyn JobAuthorizer>,
    ) -> Result<HeartbeatWorkerResult> {
        if num_cpus == 0 {
            bail!("Invalid number of CPUs (0) specified in heartbeat")
        }

        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut workers = self.workers.lock().unwrap();

        self.prune_workers(&mut workers, &mut jobs);

        match workers.get_mut(&worker_url) {
            Some(ref mut details) if details.worker_nonce == worker_nonce => {
                let now = Instant::now();
                details.last_seen = now;

                let mut stale_jobs = Vec::new();
                for (&job_id, &last_seen) in details.jobs_unclaimed.iter() {
                    if now.duration_since(last_seen) < UNCLAIMED_READY_TIMEOUT {
                        continue;
                    }
                    if let Some(detail) = jobs.get(&job_id) {
                        match detail.state {
                            JobState::Ready => {
                                stale_jobs.push(job_id);
                            }
                            JobState::Pending => {
                                if now.duration_since(last_seen) > UNCLAIMED_PENDING_TIMEOUT {
                                    stale_jobs.push(job_id);
                                }
                            }
                            state => {
                                warn!("Invalid unclaimed job state for {}: {}", job_id, state);
                            }
                        }
                    } else {
                        warn!("Unknown stale job {}", job_id);
                        stale_jobs.push(job_id);
                    }
                }

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );

                    for job_id in stale_jobs {
                        if !details.jobs_assigned.remove(&job_id) {
                            warn!(
                                "Stale job for server {} not assigned: {}",
                                &worker_url, job_id
                            );
                        }
                        if details.jobs_unclaimed.remove(&job_id).is_none() {
                            warn!("Unknown stale job for worker {}: {}", worker_url, job_id);
                        }
                        if jobs.remove(&job_id).is_none() {
                            warn!("Unknown stale job for worker {}: {}", worker_url, job_id);
                        }
                    }
                }

                return Ok(HeartbeatWorkerResult { is_new: false });
            }
            Some(ref mut details) if details.worker_nonce != worker_nonce => {
                for job_id in details.jobs_assigned.iter() {
                    if jobs.remove(job_id).is_none() {
                        warn!(
                            "Unknown job found when replacing server {}: {}",
                            worker_url, job_id
                        );
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {:?}", worker_url);
        workers.insert(
            worker_url,
            WorkerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned: HashSet::new(),
                jobs_unclaimed: HashMap::new(),
                num_cpus,
                worker_nonce,
                job_authorizer,
            },
        );
        Ok(HeartbeatWorkerResult { is_new: true })
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        worker_url: WorkerUrl,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.workers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.worker_url != worker_url {
                bail!(
                    "Job id {} is not registed on server {:?}",
                    job_id,
                    worker_url
                )
            }

            let now = Instant::now();
            let mut server_details = servers.get_mut(&worker_url);
            if let Some(ref mut details) = server_details {
                details.last_seen = now;
            };

            match (job_detail.state, job_state) {
                (JobState::Pending, JobState::Ready) => entry.get_mut().state = job_state,
                (JobState::Ready, JobState::Started) => {
                    if let Some(details) = server_details {
                        details.jobs_unclaimed.remove(&job_id);
                    } else {
                        warn!("Job state updated, but worker is not known to scheduler")
                    }
                    entry.get_mut().state = job_state
                }
                (JobState::Started, JobState::Complete) => {
                    let (job_id, _) = entry.remove_entry();
                    if let Some(entry) = server_details {
                        assert!(entry.jobs_assigned.remove(&job_id))
                    } else {
                        bail!("Job was marked as finished, but worker is not known to scheduler")
                    }
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else {
            bail!("Unknown job")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.workers.lock().unwrap();

        self.prune_workers(&mut servers, &mut jobs);

        Ok(SchedulerStatusResult {
            num_servers: servers.len(),
            num_cpus: servers.values().map(|v| v.num_cpus).sum(),
            in_progress: jobs.len(),
        })
    }
}

pub struct Worker {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    job_toolchains: tokio::sync::Mutex<HashMap<JobId, Toolchain>>,
}

impl Worker {
    pub fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
    ) -> Result<Worker> {
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Worker {
            builder,
            cache: Mutex::new(cache),
            job_toolchains: tokio::sync::Mutex::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl WorkerIncoming for Worker {
    async fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_toolchain(&tc);
        assert!(self
            .job_toolchains
            .lock()
            .await
            .insert(job_id, tc)
            .is_none());
        let state = if need_toolchain {
            JobState::Pending
        } else {
            // TODO: can start prepping the build environment now
            JobState::Ready
        };
        Ok(AssignJobResult {
            state,
            need_toolchain,
        })
    }
    async fn handle_submit_toolchain(
        &self,
        requester: &dyn WorkerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader<'_>,
    ) -> Result<SubmitToolchainResult> {
        requester
            .do_update_job_state(job_id, JobState::Ready)
            .await
            .context("Updating job state failed")?;
        // TODO: need to lock the toolchain until the container has started
        // TODO: can start prepping container
        let tc = match self.job_toolchains.lock().await.get(&job_id).cloned() {
            Some(tc) => tc,
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        let mut cache = self.cache.lock().unwrap();
        // TODO: this returns before reading all the data, is that valid?
        if cache.contains_toolchain(&tc) {
            return Ok(SubmitToolchainResult::Success);
        }
        Ok(cache
            .insert_with(&tc, |mut file| {
                io::copy(&mut { tc_rdr }, &mut file).map(|_| ())
            })
            .map(|_| SubmitToolchainResult::Success)
            .unwrap_or(SubmitToolchainResult::CannotCache))
    }
    async fn handle_run_job(
        &self,
        requester: &dyn WorkerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader<'_>,
    ) -> Result<RunJobResult> {
        requester
            .do_update_job_state(job_id, JobState::Started)
            .await
            .context("Updating job state failed")?;
        let tc = self.job_toolchains.lock().await.remove(&job_id);
        let res = match tc {
            None => Ok(RunJobResult::JobNotFound),
            Some(tc) => {
                match self
                    .builder
                    .run_build(tc, command, outputs, inputs_rdr, &self.cache)
                {
                    Err(e) => Err(e.context("run build failed")),
                    Ok(res) => Ok(RunJobResult::Complete(JobComplete {
                        output: res.output,
                        outputs: res.outputs,
                    })),
                }
            }
        };
        requester
            .do_update_job_state(job_id, JobState::Complete)
            .await
            .context("Updating job state failed")?;
        res
    }
}
