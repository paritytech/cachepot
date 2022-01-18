#[cfg(any(feature = "dist-client", feature = "dist-worker"))]
use cachepot::config::{HTTPUrl, WorkerUrl};
use cachepot::coordinator::CoordinatorInfo;
use cachepot::dist::{self, SchedulerStatusResult};
use cachepot::util::fs;
use std::env;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde::Serialize;
#[cfg(feature = "dist-worker")]
use tokio::task::JoinHandle;
use uuid::Uuid;

const CONTAINER_NAME_PREFIX: &str = "cachepot_dist_test";
const DIST_IMAGE: &str = "cachepot_dist_test_image";
const DIST_DOCKERFILE: &str = include_str!("Dockerfile.cachepot-dist");
const DIST_IMAGE_BWRAP_PATH: &str = "/bwrap";
const MAX_STARTUP_WAIT: Duration = Duration::from_secs(5);

const DIST_WORKER_TOKEN: &str = "THIS IS THE TEST TOKEN";

const CONFIGS_CONTAINER_PATH: &str = "/cachepot-bits";
const BUILD_DIR_CONTAINER_PATH: &str = "/cachepot-bits/build-dir";
const SCHEDULER_PORT: u16 = 10500;
const SERVER_PORT: u16 = 12345; // arbitrary

const TC_CACHE_SIZE: u64 = 1024 * 1024 * 1024; // 1 gig

pub fn start_local_daemon(cfg_path: &Path, cached_cfg_path: &Path) {
    // Don't run this with run() because on Windows `wait_with_output`
    // will hang because the internal server process is not detached.
    trace!("cachepot --start-coordinator");
    let _status = cachepot_command()
        .arg("--start-coordinator")
        .env("CACHEPOT_CONF", cfg_path)
        .env("CACHEPOT_CACHED_CONF", cached_cfg_path)
        .status()
        .unwrap()
        .success();
}
pub fn stop_local_daemon() {
    trace!("cachepot --stop-coordinator");
    drop(
        cachepot_command()
            .arg("--stop-coordinator")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

pub fn get_stats<F: 'static + Fn(CoordinatorInfo)>(f: F) {
    cachepot_command()
        .args(&["--show-stats", "--stats-format=json"])
        .assert()
        .success()
        .stdout(predicate::function(move |output: &[u8]| {
            let s = str::from_utf8(output).expect("Output not UTF-8");
            f(serde_json::from_str(s).expect("Failed to parse JSON stats"));
            true
        }));
}

#[allow(unused)]
pub fn zero_stats() {
    trace!("cachepot --zero-stats");
    drop(
        cachepot_command()
            .arg("--zero-stats")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

pub fn write_json_cfg<T: Serialize>(path: &Path, filename: &str, contents: &T) {
    let p = path.join(filename);
    let mut f = fs::File::create(&p).unwrap();
    f.write_all(&serde_json::to_vec(contents).unwrap()).unwrap();
}

pub fn write_source(path: &Path, filename: &str, contents: &str) {
    let p = path.join(filename);
    let mut f = fs::File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

// Prune any environment variables that could adversely affect test execution.
pub fn cachepot_command() -> Command {
    use cachepot::util::OsStrExt;

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin(env!("CARGO_PKG_NAME")));
    for (var, _) in env::vars_os() {
        if var.starts_with("CACHEPOT_") {
            cmd.env_remove(var);
        }
    }
    cmd
}

#[cfg(feature = "dist-worker")]
pub fn cachepot_dist_path() -> PathBuf {
    assert_cmd::cargo::cargo_bin("cachepot-dist")
}

pub fn cachepot_client_cfg(tmpdir: &Path) -> cachepot::config::FileConfig {
    let cache_relpath = "client-cache";
    let dist_cache_relpath = "client-dist-cache";
    fs::create_dir(tmpdir.join(cache_relpath)).unwrap();
    fs::create_dir(tmpdir.join(dist_cache_relpath)).unwrap();

    let disk_cache = cachepot::config::DiskCacheConfig {
        dir: tmpdir.join(cache_relpath),
        ..Default::default()
    };
    cachepot::config::FileConfig {
        cache: cachepot::config::CacheConfigs {
            azure: None,
            disk: Some(disk_cache),
            gcs: None,
            memcached: None,
            redis: None,
            s3: None,
        },
        dist: cachepot::config::DistConfig {
            auth: Default::default(), // dangerously_insecure
            scheduler_url: None,
            cache_dir: tmpdir.join(dist_cache_relpath),
            toolchains: vec![],
            toolchain_cache_size: TC_CACHE_SIZE,
            rewrite_includes_only: false, // TODO
        },
    }
}
#[cfg(feature = "dist-worker")]
fn cachepot_scheduler_cfg() -> cachepot::config::scheduler::Config {
    cachepot::config::scheduler::Config {
        public_addr: HTTPUrl::from_str(&format!("http://0.0.0.0:{}", SCHEDULER_PORT)).unwrap(),
        client_auth: cachepot::config::scheduler::ClientAuth::Insecure,
        worker_auth: cachepot::config::scheduler::WorkerAuth::Token {
            token: DIST_WORKER_TOKEN.to_owned(),
        },
    }
}
#[cfg(feature = "dist-worker")]
fn cachepot_server_cfg(
    tmpdir: &Path,
    scheduler_url: HTTPUrl,
    server_ip: IpAddr,
) -> cachepot::config::worker::Config {
    let relpath = "server-cache";
    fs::create_dir(tmpdir.join(relpath)).unwrap();

    cachepot::config::worker::Config {
        builder: cachepot::config::worker::BuilderType::Overlay {
            build_dir: BUILD_DIR_CONTAINER_PATH.into(),
            bwrap_path: DIST_IMAGE_BWRAP_PATH.into(),
        },
        cache_dir: Path::new(CONFIGS_CONTAINER_PATH).join(relpath),
        public_addr: WorkerUrl::from_str(&format!("{}:{}", server_ip, SERVER_PORT)).unwrap(),
        scheduler_url,
        scheduler_auth: cachepot::config::worker::SchedulerAuth::Token {
            token: DIST_WORKER_TOKEN.to_owned(),
        },
        toolchain_cache_size: TC_CACHE_SIZE,
    }
}

// TODO: this is copied from the cachepot-dist binary - it's not clear where would be a better place to put the
// code so that it can be included here
#[cfg(feature = "dist-worker")]
fn create_server_token(worker_url: WorkerUrl, auth_token: &str) -> String {
    format!("{} {}", worker_url, auth_token)
}

#[cfg(feature = "dist-worker")]
pub enum ServerHandle {
    Container {
        cid: String,
        url: HTTPUrl,
    },
    AsyncTask {
        handle: JoinHandle<()>,
        url: HTTPUrl,
    },
}

#[cfg(feature = "dist-worker")]
pub struct DistSystem {
    cachepot_dist: PathBuf,
    tmpdir: PathBuf,

    scheduler_name: Option<String>,
    server_names: Vec<String>,
    server_handles: Vec<JoinHandle<()>>,
    client: reqwest::Client,
}

#[cfg(feature = "dist-worker")]
impl DistSystem {
    pub fn new(cachepot_dist: &Path, tmpdir: &Path) -> Self {
        // Make sure the docker image is available, building it if necessary
        let mut child = Command::new("docker")
            .args(&["build", "-q", "-t", DIST_IMAGE, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(DIST_DOCKERFILE.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        check_output(&output);

        let tmpdir = tmpdir.join("distsystem");
        fs::create_dir(&tmpdir).unwrap();

        let client = native_tls_no_sni_client_builder_danger().build().unwrap();

        Self {
            cachepot_dist: cachepot_dist.to_owned(),
            tmpdir,

            scheduler_name: None,
            server_names: vec![],
            server_handles: vec![],
            client,
        }
    }

    pub async fn add_scheduler(&mut self) {
        let scheduler_cfg_relpath = "scheduler-cfg.json";
        let scheduler_cfg_path = self.tmpdir.join(scheduler_cfg_relpath);
        let scheduler_cfg_container_path =
            Path::new(CONFIGS_CONTAINER_PATH).join(scheduler_cfg_relpath);
        let scheduler_cfg = cachepot_scheduler_cfg();
        fs::File::create(&scheduler_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&scheduler_cfg).unwrap())
            .unwrap();

        // Create the scheduler
        let scheduler_name = make_container_name("scheduler");
        let output = Command::new("docker")
            .args(&[
                "run",
                "--name",
                &scheduler_name,
                "-e",
                "CACHEPOT_NO_DAEMON=1",
                "-e",
                "RUST_LOG=cachepot=trace",
                "-e",
                "RUST_BACKTRACE=1",
                "-v",
                &format!("{}:/cachepot-dist", self.cachepot_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}",
                    self.tmpdir.to_str().unwrap(),
                    CONFIGS_CONTAINER_PATH
                ),
                "-d",
                DIST_IMAGE,
                "bash",
                "-c",
                &format!(
                    r#"
                    set -o errexit &&
                    exec /cachepot-dist scheduler --config {cfg}
                "#,
                    cfg = scheduler_cfg_container_path.to_str().unwrap()
                ),
            ])
            .output()
            .unwrap();
        self.scheduler_name = Some(scheduler_name);

        check_output(&output);

        let scheduler_url = self.scheduler_url();

        wait_for_http(
            &self.client,
            scheduler_url,
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        )
        .await;

        let status_fut = async move {
            loop {
                let status = self.scheduler_status();

                tokio::select! {
                    s = status => {
                        if matches!(
                            s,
                            SchedulerStatusResult {
                                num_servers: 0,
                                num_cpus: _,
                                in_progress: 0
                        }
                        ) {
                            break Ok(());
                        } else {
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        };

        wait_for(status_fut, MAX_STARTUP_WAIT).await;
    }

    pub async fn add_server(&mut self) -> ServerHandle {
        let server_cfg_relpath = format!("server-cfg-{}.json", self.server_names.len());
        let server_cfg_path = self.tmpdir.join(&server_cfg_relpath);
        let server_cfg_container_path = Path::new(CONFIGS_CONTAINER_PATH).join(server_cfg_relpath);

        let server_name = make_container_name("server");
        let output = Command::new("docker")
            .args(&[
                "run",
                // Important for the bubblewrap builder
                "--privileged",
                "--name",
                &server_name,
                "-e",
                "RUST_LOG=cachepot=trace",
                "-e",
                "RUST_BACKTRACE=1",
                "-v",
                &format!("{}:/cachepot-dist", self.cachepot_dist.to_str().unwrap()),
                "-v",
                &format!(
                    "{}:{}",
                    self.tmpdir.to_str().unwrap(),
                    CONFIGS_CONTAINER_PATH
                ),
                "-d",
                DIST_IMAGE,
                "bash",
                "-c",
                &format!(
                    r#"
                    set -o errexit &&
                    while [ ! -f {cfg}.ready ]; do sleep 0.1; done &&
                    exec /cachepot-dist worker --config {cfg}
                "#,
                    cfg = server_cfg_container_path.to_str().unwrap()
                ),
            ])
            .output()
            .unwrap();
        self.server_names.push(server_name.clone());

        check_output(&output);

        let server_ip = self.container_ip(&server_name);
        let server_cfg = cachepot_server_cfg(&self.tmpdir, self.scheduler_url(), server_ip);
        fs::File::create(&server_cfg_path)
            .unwrap()
            .write_all(&serde_json::to_vec(&server_cfg).unwrap())
            .unwrap();
        fs::File::create(format!("{}.ready", server_cfg_path.to_str().unwrap())).unwrap();

        let url = HTTPUrl::from_url(
            reqwest::Url::parse(&format!("https://{}:{}", server_ip, SERVER_PORT)).unwrap(),
        );
        let handle = ServerHandle::Container {
            cid: server_name,
            url,
        };
        self.wait_server_ready(&handle).await;
        handle
    }

    pub async fn add_custom_server<S: dist::WorkerIncoming + 'static>(
        &mut self,
        handler: S,
    ) -> ServerHandle {
        let server_addr = {
            let ip = self.host_interface_ip();
            let listener = tokio::net::TcpListener::bind(SocketAddr::from((ip, 0)))
                .await
                .unwrap();
            WorkerUrl::from_str(&format!("{}", listener.local_addr().unwrap())).unwrap()
        };
        let token = create_server_token(server_addr.clone(), DIST_WORKER_TOKEN);
        let server = dist::http::Worker::new(
            server_addr.0.to_url().clone(),
            self.scheduler_url().to_url().clone(),
            token,
            handler,
        )
        .unwrap();
        let handle = tokio::spawn(async move { void::unreachable(server.start().await.unwrap()) });
        //self.server_handles.push(handle);

        let url =
            HTTPUrl::from_url(reqwest::Url::parse(&format!("https://{}", server_addr)).unwrap());
        let handle = ServerHandle::AsyncTask { handle, url };
        self.wait_server_ready(&handle).await;
        handle
    }

    pub async fn restart_server(&mut self, handle: &ServerHandle) {
        match handle {
            ServerHandle::Container { cid, url: _ } => {
                let output = Command::new("docker")
                    .args(&["restart", cid])
                    .output()
                    .unwrap();
                check_output(&output);
            }
            ServerHandle::AsyncTask { handle: _, url: _ } => {
                // TODO: pretty easy, just no need yet
                panic!("restart not yet implemented for pids")
            }
        }
        self.wait_server_ready(handle).await
    }

    pub async fn wait_server_ready(&mut self, handle: &ServerHandle) {
        let url = match handle {
            ServerHandle::Container { cid: _, url }
            | ServerHandle::AsyncTask { handle: _, url } => url.clone(),
        };
        wait_for_http(
            &self.client,
            url,
            Duration::from_millis(100),
            MAX_STARTUP_WAIT,
        )
        .await;
        let status_fut = async move {
            loop {
                let status = self.scheduler_status();

                tokio::select! {
                    s = status => {
                        if matches!(
                            s,
                            SchedulerStatusResult {
                                num_servers: 1,
                                num_cpus: _,
                                in_progress: 0
                            }
                        ) {
                            break Ok(());
                        } else {
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        };

        wait_for(status_fut, MAX_STARTUP_WAIT).await;
    }

    pub fn scheduler_url(&self) -> HTTPUrl {
        let ip = self.container_ip(self.scheduler_name.as_ref().unwrap());
        let url = format!("http://{}:{}", ip, SCHEDULER_PORT);
        HTTPUrl::from_url(reqwest::Url::parse(&url).unwrap())
    }

    async fn scheduler_status(&self) -> SchedulerStatusResult {
        let url = dist::http::urls::scheduler_status(&self.scheduler_url().to_url());
        let res = self.client.get(url).send().await.unwrap();
        assert!(res.status().is_success());
        let bytes = res.bytes().await.unwrap();

        bincode::deserialize_from(bytes.as_ref()).unwrap()
    }

    fn container_ip(&self, name: &str) -> IpAddr {
        let output = Command::new("docker")
            .args(&[
                "inspect",
                "--format",
                "{{ .NetworkSettings.IPAddress }}",
                name,
            ])
            .output()
            .unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned().parse().unwrap()
    }

    // The interface that the host sees on the docker network (typically 'docker0')
    fn host_interface_ip(&self) -> IpAddr {
        let output = Command::new("docker")
            .args(&[
                "inspect",
                "--format",
                "{{ .NetworkSettings.Gateway }}",
                self.scheduler_name.as_ref().unwrap(),
            ])
            .output()
            .unwrap();
        check_output(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_owned().parse().unwrap()
    }
}

// If you want containers to hang around (e.g. for debugging), commend out the "rm -f" lines
#[cfg(feature = "dist-worker")]
impl Drop for DistSystem {
    fn drop(&mut self) {
        let mut did_err = false;

        // Panicking halfway through drop would either abort (if it's a double panic) or leave us with
        // resources that aren't yet cleaned up. Instead, do as much as possible then decide what to do
        // at the end - panic (if not already doing so) or let the panic continue
        macro_rules! droperr {
            ($e:expr) => {
                match $e {
                    Ok(()) => (),
                    Err(e) => {
                        did_err = true;
                        eprintln!("Error with {}: {}", stringify!($e), e)
                    }
                }
            };
        }

        let mut logs = vec![];
        let mut outputs = vec![];

        if let Some(scheduler_name) = self.scheduler_name.as_ref() {
            droperr!(Command::new("docker")
                .args(&["logs", scheduler_name])
                .output()
                .map(|o| logs.push((scheduler_name, o))));
            droperr!(Command::new("docker")
                .args(&["kill", scheduler_name])
                .output()
                .map(|o| outputs.push((scheduler_name, o))));
            droperr!(Command::new("docker")
                .args(&["rm", "-f", scheduler_name])
                .output()
                .map(|o| outputs.push((scheduler_name, o))));
        }
        for server_name in self.server_names.iter() {
            droperr!(Command::new("docker")
                .args(&["logs", server_name])
                .output()
                .map(|o| logs.push((server_name, o))));
            droperr!(Command::new("docker")
                .args(&["kill", server_name])
                .output()
                .map(|o| outputs.push((server_name, o))));
            droperr!(Command::new("docker")
                .args(&["rm", "-f", server_name])
                .output()
                .map(|o| outputs.push((server_name, o))));
        }
        // TODO: they will die with the runtime, but correctly waiting for them
        // may be only possible when we have async Drop.
        for _handle in self.server_handles.iter() {}

        for (
            container,
            Output {
                status,
                stdout,
                stderr,
            },
        ) in logs
        {
            println!(
                "LOGS == ({}) ==\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                status,
                container,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        for (
            container,
            Output {
                status,
                stdout,
                stderr,
            },
        ) in outputs
        {
            println!(
                "OUTPUTS == ({}) ==\n> {} <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
                status,
                container,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }

        if did_err && !thread::panicking() {
            panic!("Encountered failures during dist system teardown")
        }
    }
}

fn make_container_name(tag: &str) -> String {
    format!(
        "{}_{}_{}",
        CONTAINER_NAME_PREFIX,
        tag,
        Uuid::new_v4().to_hyphenated_ref()
    )
}

fn check_output(output: &Output) {
    if !output.status.success() {
        println!("{}\n\n[BEGIN STDOUT]\n===========\n{}\n===========\n[FIN STDOUT]\n\n[BEGIN STDERR]\n===========\n{}\n===========\n[FIN STDERR]\n\n",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        panic!()
    }
}

#[cfg(feature = "dist-worker")]
fn native_tls_no_sni_client_builder_danger() -> reqwest::ClientBuilder {
    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .use_sni(false)
        .build()
        .unwrap();

    reqwest::ClientBuilder::new()
        .use_native_tls()
        .use_preconfigured_tls(tls)
}

#[cfg(feature = "dist-worker")]
async fn wait_for_http(
    client: &reqwest::Client,
    url: HTTPUrl,
    interval: Duration,
    max_wait: Duration,
) {
    let try_connect = async move {
        let url = url.to_url();

        loop {
            match tokio::time::timeout(interval, client.get(url.clone()).send()).await {
                Ok(Ok(_)) => {
                    break;
                }
                _ => {}
            };
        }
    };

    if let Err(e) = tokio::time::timeout(max_wait, try_connect).await {
        panic!("wait timed out, last error result: {}", e)
    }
}

async fn wait_for<F: std::future::Future<Output = Result<(), String>>>(f: F, max_wait: Duration) {
    tokio::time::timeout(max_wait, f)
        .await
        .unwrap()
        .expect("wait timed out")
}
