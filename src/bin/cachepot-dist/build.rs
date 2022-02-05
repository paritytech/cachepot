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

use anyhow::{anyhow, bail, Context, Error, Result};
use cachepot::dist::{
    BuildResult, BuilderIncoming, CompileCommand, InputsReader, OutputData, ProcessOutput, TcCache,
    Toolchain,
};
use cachepot::lru_disk_cache::Error as LruError;
use cachepot::util::fs;
use flate2::read::GzDecoder;
use libmount::Overlay;
use std::collections::{hash_map, HashMap};
use std::io::{self, Cursor};
use std::iter;
use std::os::unix::net::UnixStream;
use std::path::{self, Path, PathBuf};
use std::process::{ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::Mutex;
use std::time::Instant;
use version_compare::Version;

trait CommandExt {
    fn check_stdout_trim(&mut self) -> Result<String>;
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()>;
    fn check_run(&mut self) -> Result<()>;
}

impl CommandExt for Command {
    fn check_stdout_trim(&mut self) -> Result<String> {
        let output = self.output().context("Failed to start command")?;
        check_output(&output)?;
        let stdout =
            String::from_utf8(output.stdout).context("Output from listing containers not UTF8")?;
        Ok(stdout.trim().to_owned())
    }
    // Should really take a FnOnce/FnBox
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()> {
        let mut process = self
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to start command")?;
        let mut stdin = process
            .stdin
            .take()
            .expect("Requested piped stdin but not present");
        pipe(&mut stdin).context("Failed to pipe input to process")?;
        let output = process
            .wait_with_output()
            .context("Failed to wait for process to return")?;
        check_output(&output)
    }
    fn check_run(&mut self) -> Result<()> {
        let output = self.output().context("Failed to start command")?;
        check_output(&output)
    }
}

fn check_output(output: &Output) -> Result<()> {
    if !output.status.success() {
        warn!(
            "===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        bail!("Command failed with status {}", output.status)
    }
    Ok(())
}

fn join_suffix<P: AsRef<Path>>(path: &Path, suffix: P) -> PathBuf {
    let suffixpath = suffix.as_ref();
    let mut components = suffixpath.components();
    if suffixpath.has_root() {
        assert_eq!(components.next(), Some(path::Component::RootDir));
    }
    path.join(components)
}

#[derive(Debug)]
struct OverlaySpec {
    build_dir: PathBuf,
    toolchain_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct DeflatedToolchain {
    path: PathBuf,
    build_count: u64,
    ctime: Instant,
}

pub struct OverlayBuilder {
    bubblewrap: PathBuf,
    dir: PathBuf,
    toolchain_dir_map: Mutex<HashMap<Toolchain, DeflatedToolchain>>,
}

impl OverlayBuilder {
    pub fn new(bubblewrap: PathBuf, dir: PathBuf) -> Result<Self> {
        info!("Creating overlay builder");

        // TODO: Check kernel support for user namespaces

        let out = Command::new(&bubblewrap)
            .arg("--version")
            .check_stdout_trim()
            .context("Failed to execute bwrap for version check")?;
        if let Some(s) = out.split_whitespace().nth(1) {
            match (Version::from("0.3.0"), Version::from(s)) {
                (Some(min), Some(seen)) => {
                    if seen < min {
                        bail!(
                            "bubblewrap 0.3.0 or later is required, got {:?} for {:?}",
                            out,
                            bubblewrap
                        );
                    }
                }
                (_, _) => {
                    bail!("Unexpected version format running {:?}: got {:?}, expected \"bubblewrap x.x.x\"",
                          bubblewrap, out);
                }
            }
        } else {
            bail!(
                "Unexpected version format running {:?}: got {:?}, expected \"bubblewrap x.x.x\"",
                bubblewrap,
                out
            );
        }

        // TODO: pidfile
        let ret = Self {
            bubblewrap,
            dir,
            toolchain_dir_map: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        fs::create_dir(&ret.dir).context("Failed to create base directory for builder")?;
        fs::create_dir(ret.dir.join("builds"))
            .context("Failed to create builder builds directory")?;
        fs::create_dir(ret.dir.join("toolchains"))
            .context("Failed to create builder toolchains directory")?;
        Ok(ret)
    }

    fn cleanup(&self) -> Result<()> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).context("Failed to clean up builder directory")?
        }
        Ok(())
    }

    fn prepare_overlay_dirs(
        &self,
        tc: &Toolchain,
        tccache: &Mutex<TcCache>,
    ) -> Result<OverlaySpec> {
        let DeflatedToolchain {
            path: toolchain_dir,
            build_count: id,
            ctime: _,
        } = {
            let mut toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
            // Create the toolchain dir (if necessary) while we have an exclusive lock
            let toolchain_dir = self.dir.join("toolchains").join(&tc.archive_id);
            if toolchain_dir_map.contains_key(tc) && toolchain_dir.exists() {
                // TODO: use if let when cachepot can use NLL
                let entry = toolchain_dir_map
                    .get_mut(tc)
                    .expect("Key missing after checking");
                entry.build_count += 1;
                entry.clone()
            } else {
                if toolchain_dir.exists() {
                    warn!(
                        "Toolchain directory for {} already exists, removing",
                        tc.archive_id
                    );
                    fs::remove_dir_all(&toolchain_dir)?;
                }
                trace!("Creating toolchain directory for {}", tc.archive_id);
                fs::create_dir(&toolchain_dir)?;

                let mut tccache = tccache.lock().unwrap();
                let toolchain_rdr = match tccache.get(tc) {
                    Ok(rdr) => rdr,
                    Err(LruError::FileNotInCache) => {
                        bail!("expected toolchain {}, but not available", tc.archive_id)
                    }
                    Err(e) => {
                        return Err(Error::from(e).context("failed to get toolchain from cache"))
                    }
                };

                tar::Archive::new(GzDecoder::new(toolchain_rdr))
                    .unpack(&toolchain_dir)
                    .or_else(|e| {
                        warn!("Failed to unpack toolchain: {:?}", e);
                        fs::remove_dir_all(&toolchain_dir)
                            .context("Failed to remove unpacked toolchain")?;
                        tccache
                            .remove(tc)
                            .context("Failed to remove corrupt toolchain")?;
                        Err(Error::from(e))
                    })?;

                let entry = DeflatedToolchain {
                    path: toolchain_dir,
                    build_count: 1,
                    ctime: Instant::now(),
                };

                toolchain_dir_map.insert(tc.clone(), entry.clone());
                if toolchain_dir_map.len() > tccache.len() {
                    let dir_map = toolchain_dir_map.clone();
                    let mut entries: Vec<_> = dir_map.iter().collect();
                    // In the pathological case, creation time for unpacked
                    // toolchains could be the opposite of the least recently
                    // recently used, so we clear out half of the accumulated
                    // toolchains to prevent repeated sort/delete cycles.
                    entries.sort_by(|a, b| (a.1).ctime.cmp(&(b.1).ctime));
                    entries.truncate(entries.len() / 2);
                    for (tc, _) in entries {
                        warn!("Removing old un-compressed toolchain: {:?}", tc);
                        assert!(toolchain_dir_map.remove(tc).is_some());
                        fs::remove_dir_all(&self.dir.join("toolchains").join(&tc.archive_id))
                            .context("Failed to remove old toolchain directory")?;
                    }
                }
                entry
            }
        };

        trace!("Creating build directory for {}-{}", tc.archive_id, id);
        let build_dir = self
            .dir
            .join("builds")
            .join(format!("{}-{}", tc.archive_id, id));
        fs::create_dir(&build_dir)?;
        Ok(OverlaySpec {
            build_dir,
            toolchain_dir,
        })
    }

    fn perform_build(
        bubblewrap: &Path,
        compile_command: CompileCommand,
        inputs_rdr: InputsReader,
        output_paths: Vec<String>,
        overlay: &OverlaySpec,
    ) -> Result<BuildResult> {
        use std::io::{Read, Write};

        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable,
            compile_command.arguments
        );

        #[derive(Serialize, Deserialize)]
        struct CompressedFile {
            path: String,
            buf: Vec<u8>,
        }
        type CompressedOutputs = Vec<CompressedFile>;

        let CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = compile_command;
        let cwd = Path::new(&cwd);

        let work_dir = overlay.build_dir.join("work");
        let upper_dir = overlay.build_dir.join("upper");
        let target_dir = overlay.build_dir.join("target");

        fs::create_dir(&work_dir).context("Failed to create overlay work directory")?;
        fs::create_dir(&upper_dir).context("Failed to create overlay upper directory")?;
        fs::create_dir(&target_dir).context("Failed to create overlay target directory")?;

        //
        let mut stdout_pipe = UnixStream::pair()?;
        let mut stderr_pipe = UnixStream::pair()?;
        let mut compressed_outputs_pipe = UnixStream::pair()?;

        // SAFETY: Unfortunately, this is *NOT* safe, since we don't only call
        // `async-signal-safe` [1] syscalls in the child process (most notably
        // this includes memory allocation). However, it's good enough for a
        // proof of concept for rootless build sandbox using user namespaces.
        // The reason why we need to fork in the first place is that creating
        // a new user namespace with `CLONE_NEWUSER` is required to be called
        // from a main thread, which fork() separates the calling thread as one.
        // FIXME: Redesign this binary to be re-executable like
        // `cachepot-dist sandbox` (akin to server/scheduler), which would enter
        // the child namespace in the init function, passing the outputs via
        // shared pipes or a shared tempdir.
        // [1]: https://man7.org/linux/man-pages/man7/signal-safety.7.html
        let pid = match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child } => {
                drop(stdout_pipe.1);
                drop(stderr_pipe.1);
                drop(compressed_outputs_pipe.1);

                child
            }
            nix::unistd::ForkResult::Child => {
                drop(stdout_pipe.0);
                drop(stderr_pipe.0);
                drop(compressed_outputs_pipe.0);

                // We need to catch these here errors so they *DON'T* escape to
                // the forked parent's context.
                // Forking is a Bad Idea^TM anyway, see note above.
                let do_work = move || -> Result<ExitStatus> {
                    // Fetch uid/gid of the parent namespace user in order to
                    // subsequently map to it in the child user namespace
                    let uid = nix::unistd::Uid::current();
                    let gid = nix::unistd::Uid::current();

                    // We must call this from a main thread, hence why we forked
                    // in the first place.
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER)
                        .context("Failed to enter a new user namespace")?;

                    // Now mounted filesystems will be automatically unmounted when this thread dies
                    // (and tmpfs filesystems will be completely destroyed)
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
                        .context("Failed to enter a new Linux namespace")?;

                    // Equivalent of `unshare --map-current-user` - we need that
                    // to mount overlayfs and access files owned by the parent
                    // namespace user
                    std::fs::write("/proc/self/uid_map", format!("{} {} 1", uid, uid))
                        .context("Failed writing to uid_map")?;
                    std::fs::write("/proc/self/setgroups", "deny")
                        .context("Failed writing to setgroups")?;
                    // FIXME: Uncomment me
                    std::fs::write("/proc/self/gid_map", format!("{} {} 1", gid, gid))
                        .context("Failed writing to gid_map")?;

                    // Make sure that all future mount changes are private to this namespace
                    // Equivalent of `unshare --propagation private` (when used with `--mount`)
                    let fstype: Option<&str> = None;
                    let data: Option<&str> = None;
                    nix::mount::mount(
                        Some("none"),
                        "/",
                        fstype,
                        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                        data,
                    )
                    .context("Failed to turn / into a slave")?;

                    Overlay::writable(
                        iter::once(overlay.toolchain_dir.as_path()),
                        upper_dir,
                        work_dir,
                        &target_dir,
                        // This error is unfortunately not Send+Sync
                    )
                    .mount()
                    .map_err(|e| anyhow!("Failed to mount overlay FS: {}", e.to_string()))?;

                    trace!("copying in inputs");
                    // Note that we don't unpack directly into the upperdir since there overlayfs has some
                    // special marker files [1] that we don't want to create by accident (or malicious intent)
                    // [1]: like https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#volatile-mount
                    tar::Archive::new(inputs_rdr)
                        .unpack(&target_dir)
                        .context("Failed to unpack inputs to overlay")?;

                    trace!("creating output directories");
                    fs::create_dir_all(join_suffix(&target_dir, cwd))
                        .context("Failed to create cwd")?;
                    for path in output_paths.iter() {
                        // If it doesn't have a parent, nothing needs creating
                        let output_parent = if let Some(p) = Path::new(path).parent() {
                            p
                        } else {
                            continue;
                        };
                        fs::create_dir_all(join_suffix(&target_dir, cwd.join(output_parent)))
                            .context("Failed to create an output directory")?;
                    }

                    trace!("performing compile");
                    // FIXME: Adapt the notes for the user namespaces
                    // Bubblewrap notes:
                    // - We're running as uid 0 (to do the mounts above), and so bubblewrap is run as uid 0
                    // - There's special handling in bubblewrap to compare uid and euid - of interest to us,
                    //   if uid == euid == 0, bubblewrap preserves capabilities (not good!) so we explicitly
                    //   drop all capabilities
                    // - By entering a new user namespace means any set of capabilities do not apply to any
                    //   other user namespace, i.e. you lose privileges. This is not strictly necessary because
                    //   we're dropping caps anyway so it's irrelevant which namespace we're in, but it doesn't
                    //   hurt.
                    // - --unshare-all is not ideal as it happily continues if it fails to unshare either
                    //   the user or cgroups namespace, so we list everything explicitly
                    // - The order of bind vs proc + dev is important - the new root must be put in place
                    //   first, otherwise proc and dev get hidden
                    let mut cmd = Command::new(bubblewrap);
                    cmd.arg("--die-with-parent")
                        .args(&["--cap-drop", "ALL"])
                        .args(&[
                            "--unshare-user",
                            "--unshare-cgroup",
                            "--unshare-ipc",
                            "--unshare-pid",
                            "--unshare-net",
                            "--unshare-uts",
                        ])
                        .arg("--bind")
                        .arg(&target_dir)
                        .arg("/")
                        .args(&["--proc", "/proc"])
                        .args(&["--dev", "/dev"])
                        .arg("--chdir")
                        .arg(cwd);

                    for (k, v) in env_vars {
                        if k.contains('=') {
                            warn!("Skipping environment variable: {:?}", k);
                            continue;
                        }
                        cmd.arg("--setenv").arg(k).arg(v);
                    }
                    cmd.arg("--");
                    cmd.arg(executable);
                    cmd.args(arguments);

                    trace!("Running bubblewrap build: {:?}", cmd);

                    let output = cmd.output().context("Error running bubblewrap")?;
                    // FIXME: Probably would be better to use some concurrent I/O here
                    stdout_pipe.1.write_all(&output.stdout).context("stdout")?;
                    stderr_pipe.1.write_all(&output.stderr).context("stderr")?;

                    let mut outputs: CompressedOutputs = vec![];
                    trace!("retrieving {:?}", output_paths);
                    for path in output_paths {
                        // Resolve in case it's relative since we copy it from the root level
                        let abspath = join_suffix(&target_dir, cwd.join(&path));
                        match fs::File::open(abspath) {
                            Ok(mut file) => {
                                let mut contents = vec![];
                                file.read_to_end(&mut contents)?;
                                // Decompress on the parent side to limit I/O
                                outputs.push(CompressedFile {
                                    path,
                                    buf: contents,
                                });
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::NotFound {
                                    debug!("Missing output path {:?}", path)
                                } else {
                                    return Err(
                                        Error::from(e).context("Failed to open output file")
                                    );
                                }
                            }
                        }
                    }

                    let compressed = bincode::serialize(&outputs)?;
                    compressed_outputs_pipe
                        .1
                        .write_all(&compressed)
                        .context("Error writing outputs to pipe")?;

                    Ok(output.status)
                };

                match do_work() {
                    Ok(status) if status.success() => std::process::exit(0),
                    Ok(status) => {
                        info!("Bubblewrap build wasn't succesful");
                        // TODO: Use ExitStatusExt::into_raw in Rust 1.58
                        std::process::exit(status.code().unwrap_or(1))
                    }

                    Err(e) => {
                        warn!("Couldn't set up a build environment for bubblewrap: {}", e);
                        std::process::exit(101)
                    }
                }
            }
        };

        trace!("Waiting on child bubblewrap build with PID {}", pid);
        use nix::sys::wait::{WaitPidFlag, WaitStatus};
        let code = match nix::sys::wait::waitpid(pid, Some(WaitPidFlag::WSTOPPED)) {
            Ok(WaitStatus::Exited(_, code)) => code,
            Ok(..) => {
                warn!("Error waiting for child build");
                return Err(anyhow!("Error waiting for a child build"));
            }
            Err(e) => {
                warn!("Error waiting for child build: {}", e);
                return Err(e)?;
            }
        };
        let mut stdout = vec![];
        let mut stderr = vec![];
        stdout_pipe.0.read_to_end(&mut stdout).context("stdout")?;
        stderr_pipe.0.read_to_end(&mut stderr).context("stderr")?;
        let mut compressed_outputs = vec![];
        compressed_outputs_pipe
            .0
            .read_to_end(&mut compressed_outputs)
            .context("Error reading compressed outputs from pipe")?;
        let compressed_outputs: CompressedOutputs = bincode::deserialize(&compressed_outputs)?;
        let outputs = compressed_outputs
            .into_iter()
            .map(|CompressedFile { path, buf }| {
                (path, OutputData::try_from_reader(Cursor::new(buf)).unwrap())
            })
            .collect();
        let compile_output = ProcessOutput {
            code,
            stdout,
            stderr,
        };
        trace!("compile_output: {:?}", compile_output);

        Ok(BuildResult {
            output: compile_output,
            outputs,
        })
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_overlay(&self, _tc: &Toolchain, overlay: OverlaySpec) {
        // TODO: collect toolchain directories

        let OverlaySpec {
            build_dir,
            toolchain_dir: _,
        } = overlay;
        if let Err(e) = fs::remove_dir_all(&build_dir) {
            error!(
                "Failed to remove build directory {}: {}",
                build_dir.display(),
                e
            );
        }
    }
}

impl BuilderIncoming for OverlayBuilder {
    fn run_build(
        &self,
        tc: Toolchain,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
        tccache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        debug!("Preparing overlay");
        let overlay = self
            .prepare_overlay_dirs(&tc, tccache)
            .context("failed to prepare overlay dirs")?;
        debug!("Performing build in {:?}", overlay);
        let res = Self::perform_build(&self.bubblewrap, command, inputs_rdr, outputs, &overlay);
        debug!("Finishing with overlay");
        self.finish_overlay(&tc, overlay);
        debug!("Returning result");
        res.context("Compilation execution failed")
    }
}

const BASE_DOCKER_IMAGE: &str = "aidanhs/busybox";
// Make sure sh doesn't exec the final command, since we need it to do
// init duties (reaping zombies). Also, because we kill -9 -1, that kills
// the sleep (it's not a builtin) so it needs to be a loop.
const DOCKER_SHELL_INIT: &str = "while true; do /busybox sleep 365d && /busybox true; done";

// Check the diff and clean up the FS
fn docker_diff(cid: &str) -> Result<String> {
    Command::new("docker")
        .args(&["diff", cid])
        .check_stdout_trim()
        .context("Failed to Docker diff container")
}

// Force remove the container
fn docker_rm(cid: &str) -> Result<()> {
    Command::new("docker")
        .args(&["rm", "-f", cid])
        .check_run()
        .context("Failed to force delete container")
}

pub struct DockerBuilder {
    image_map: Mutex<HashMap<Toolchain, String>>,
    container_lists: Mutex<HashMap<Toolchain, Vec<String>>>,
}

impl DockerBuilder {
    // TODO: this should accept a unique string, e.g. inode of the tccache directory
    // having locked a pidfile, or at minimum should loudly detect other running
    // instances - pidfile in /tmp
    pub fn new() -> Result<Self> {
        info!("Creating docker builder");

        let ret = Self {
            image_map: Mutex::new(HashMap::new()),
            container_lists: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        Ok(ret)
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup(&self) -> Result<()> {
        info!("Performing initial Docker cleanup");

        let containers = Command::new("docker")
            .args(&["ps", "-a", "--format", "{{.ID}} {{.Image}}"])
            .check_stdout_trim()
            .context("Unable to list all Docker containers")?;
        if !containers.is_empty() {
            let mut containers_to_rm = vec![];
            for line in containers.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let container_id = iter
                    .next()
                    .context("Malformed container listing - no container ID")?;
                let image_name = iter
                    .next()
                    .context("Malformed container listing - no image name")?;
                if iter.next() != None {
                    bail!("Malformed container listing - third field on row")
                }
                if image_name.starts_with("cachepot-builder-") {
                    containers_to_rm.push(container_id)
                }
            }
            if !containers_to_rm.is_empty() {
                Command::new("docker")
                    .args(&["rm", "-f"])
                    .args(containers_to_rm)
                    .check_run()
                    .context("Failed to start command to remove old containers")?;
            }
        }

        let images = Command::new("docker")
            .args(&["images", "--format", "{{.ID}} {{.Repository}}"])
            .check_stdout_trim()
            .context("Failed to list all docker images")?;
        if !images.is_empty() {
            let mut images_to_rm = vec![];
            for line in images.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let image_id = iter
                    .next()
                    .context("Malformed image listing - no image ID")?;
                let image_name = iter
                    .next()
                    .context("Malformed image listing - no image name")?;
                if iter.next() != None {
                    bail!("Malformed image listing - third field on row")
                }
                if image_name.starts_with("cachepot-builder-") {
                    images_to_rm.push(image_id)
                }
            }
            if !images_to_rm.is_empty() {
                Command::new("docker")
                    .args(&["rmi"])
                    .args(images_to_rm)
                    .check_run()
                    .context("Failed to remove image")?
            }
        }

        info!("Completed initial Docker cleanup");
        Ok(())
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Docker image along
    // the way)
    fn get_container(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let container = {
            let mut map = self.container_lists.lock().unwrap();
            map.entry(tc.clone()).or_insert_with(Vec::new).pop()
        };
        match container {
            Some(cid) => Ok(cid),
            None => {
                // TODO: can improve parallelism (of creating multiple images at a time) by using another
                // (more fine-grained) mutex around the entry value and checking if its empty a second time
                let image = {
                    let mut map = self.image_map.lock().unwrap();
                    match map.entry(tc.clone()) {
                        hash_map::Entry::Occupied(e) => e.get().clone(),
                        hash_map::Entry::Vacant(e) => {
                            info!("Creating Docker image for {:?} (may block requests)", tc);
                            let image = Self::make_image(tc, tccache)?;
                            e.insert(image.clone());
                            image
                        }
                    }
                };
                Self::start_container(&image)
            }
        }
    }

    fn clean_container(&self, cid: &str) -> Result<()> {
        // Clean up any running processes
        Command::new("docker")
            .args(&["exec", cid, "/busybox", "kill", "-9", "-1"])
            .check_run()
            .context("Failed to run kill on all processes in container")?;

        let diff = docker_diff(cid)?;
        if !diff.is_empty() {
            let mut lastpath = None;
            for line in diff.split(|c| c == '\n') {
                let mut iter = line.splitn(2, ' ');
                let changetype = iter
                    .next()
                    .context("Malformed container diff - no change type")?;
                let changepath = iter
                    .next()
                    .context("Malformed container diff - no change path")?;
                if iter.next() != None {
                    bail!("Malformed container diff - third field on row")
                }
                // TODO: If files are created in this dir, it gets marked as modified.
                // A similar thing applies to /root or /build etc
                if changepath == "/tmp" {
                    continue;
                }
                if changetype != "A" {
                    bail!(
                        "Path {} had a non-A changetype of {}",
                        changepath,
                        changetype
                    );
                }
                // Docker diff paths are in alphabetical order and we do `rm -rf`, so we might be able to skip
                // calling Docker more than necessary (since it's slow)
                if let Some(lastpath) = lastpath {
                    if Path::new(changepath).starts_with(lastpath) {
                        continue;
                    }
                }
                lastpath = Some(changepath);
                if let Err(e) = Command::new("docker")
                    .args(&["exec", cid, "/busybox", "rm", "-rf", changepath])
                    .check_run()
                {
                    // We do a final check anyway, so just continue
                    warn!("Failed to remove added path in a container: {}", e)
                }
            }

            let newdiff = docker_diff(cid)?;
            // See note about changepath == "/tmp" above
            if !newdiff.is_empty() && newdiff != "C /tmp" {
                bail!(
                    "Attempted to delete files, but container still has a diff: {:?}",
                    newdiff
                );
            }
        }

        Ok(())
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_container(&self, tc: &Toolchain, cid: String) {
        // TODO: collect images

        if let Err(e) = self.clean_container(&cid) {
            info!("Failed to clean container {}: {}", cid, e);
            if let Err(e) = docker_rm(&cid) {
                warn!(
                    "Failed to remove container {} after failed clean: {}",
                    cid, e
                );
            }
            return;
        }

        // Good as new, add it back to the container list
        if let Some(entry) = self.container_lists.lock().unwrap().get_mut(tc) {
            debug!("Reclaimed container {}", cid);
            entry.push(cid)
        } else {
            warn!(
                "Was ready to reclaim container {} but toolchain went missing",
                cid
            );
            if let Err(e) = docker_rm(&cid) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
    }

    fn make_image(tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let cid = Command::new("docker")
            .args(&["create", BASE_DOCKER_IMAGE, "/busybox", "true"])
            .check_stdout_trim()
            .context("Failed to create docker container")?;

        let mut tccache = tccache.lock().unwrap();
        let mut toolchain_rdr = match tccache.get(tc) {
            Ok(rdr) => rdr,
            Err(LruError::FileNotInCache) => bail!(
                "Expected to find toolchain {}, but not available",
                tc.archive_id
            ),
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to use toolchain {}", tc.archive_id))
            }
        };

        trace!("Copying in toolchain");
        Command::new("docker")
            .args(&["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| {
                io::copy(&mut toolchain_rdr, stdin)?;
                Ok(())
            })
            .context("Failed to copy toolchain tar into container")?;
        drop(toolchain_rdr);

        let imagename = format!("cachepot-builder-{}", &tc.archive_id);
        Command::new("docker")
            .args(&["commit", &cid, &imagename])
            .check_run()
            .context("Failed to commit container after build")?;

        Command::new("docker")
            .args(&["rm", "-f", &cid])
            .check_run()
            .context("Failed to remove temporary build container")?;

        Ok(imagename)
    }

    fn start_container(image: &str) -> Result<String> {
        Command::new("docker")
            .args(&[
                "run",
                "-d",
                image,
                "/busybox",
                "sh",
                "-c",
                DOCKER_SHELL_INIT,
            ])
            .check_stdout_trim()
            .context("Failed to run container")
    }

    fn perform_build(
        compile_command: CompileCommand,
        mut inputs_rdr: InputsReader,
        output_paths: Vec<String>,
        cid: &str,
    ) -> Result<BuildResult> {
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable,
            compile_command.arguments
        );

        trace!("copying in inputs");
        Command::new("docker")
            .args(&["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| {
                io::copy(&mut inputs_rdr, stdin)?;
                Ok(())
            })
            .context("Failed to copy inputs tar into container")?;
        drop(inputs_rdr);

        let CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        assert!(!output_paths.is_empty());
        let mut cmd = Command::new("docker");
        cmd.args(&["exec", cid, "/busybox", "mkdir", "-p"]).arg(cwd);
        for path in output_paths.iter() {
            // If it doesn't have a parent, nothing needs creating
            let output_parent = if let Some(p) = Path::new(path).parent() {
                p
            } else {
                continue;
            };
            cmd.arg(cwd.join(output_parent));
        }
        cmd.check_run()
            .context("Failed to create directories required for compile in container")?;

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in env_vars {
            if k.contains('=') {
                warn!("Skipping environment variable: {:?}", k);
                continue;
            }
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = "cd \"$1\" && shift && exec \"$@\"";
        cmd.args(&[cid, "/busybox", "sh", "-c", shell_cmd]);
        cmd.arg(&executable);
        cmd.arg(cwd);
        cmd.arg(executable);
        cmd.args(arguments);
        let compile_output = cmd.output().context("Failed to start executing compile")?;
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let abspath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
                                           // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker")
                .args(&["exec", cid, "/busybox", "cat"])
                .arg(abspath)
                .output()
                .context("Failed to start command to retrieve output file")?;
            if output.status.success() {
                let output = OutputData::try_from_reader(&*output.stdout)
                    .expect("Failed to read compress output stdout");
                outputs.push((path, output))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        let compile_output = ProcessOutput::try_from(compile_output)
            .context("Failed to convert compilation exit status")?;
        Ok(BuildResult {
            output: compile_output,
            outputs,
        })
    }
}

impl BuilderIncoming for DockerBuilder {
    // From Coordinator
    fn run_build(
        &self,
        tc: Toolchain,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
        tccache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        debug!("Finding container");
        let cid = self
            .get_container(&tc, tccache)
            .context("Failed to get a container for build")?;
        debug!("Performing build with container {}", cid);
        let res = Self::perform_build(command, inputs_rdr, outputs, &cid)
            .context("Failed to perform build")?;
        debug!("Finishing with container {}", cid);
        self.finish_container(&tc, cid);
        debug!("Returning result");
        Ok(res)
    }
}
