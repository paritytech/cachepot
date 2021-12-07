# FROM rust:1.57
FROM quay.io/podman/stable

WORKDIR /cachepot

ADD ./src src
ADD Cargo.toml Cargo.lock ./

RUN dnf install -y rust cargo openssl-devel

# RUN apt-get update && \
# 	apt-get install -y curl

RUN cargo build --all-targets --all-features

ADD ./tests tests

RUN cargo build --tests --all-targets --features dist-tests

CMD [ "cargo", "test", "--locked", "--all-targets", "--no-default-features", "--features=dist-tests", "test_dist_" ]