#!/bin/bash

DOCKER_CONTEXT_DIR=context

# cargo build --bin cachepot-dist --release --features="dist-worker"

cp Cargo.lock $DOCKER_CONTEXT_DIR/
cp Cargo.toml $DOCKER_CONTEXT_DIR/
cp -r .cargo $DOCKER_CONTEXT_DIR/
cp -r src $DOCKER_CONTEXT_DIR/
cp -r tests $DOCKER_CONTEXT_DIR/

docker build --file systemd/Dockerfile.build.cachepot-dist -t cachepot-dist-test $DOCKER_CONTEXT_DIR

docker run -it \
  --env CACHEPOT_LOG="cachepot=trace" \
  --env RUST_BACKTRACE=1 \
  --env CACHEPOT_NO_DAEMON=1 \
  --env CACHEPOT_SANDBOX=userns \
  --env DIST_EXEC_STRATEGY=spawn \
  --volume ${PWD}/target:/cachepot/target \
  --security-opt seccomp=moby_seccomp_default.json \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  cachepot-dist-test $@
  # -v /proc:/newproc \
#   /bin/bash
