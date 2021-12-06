FROM rust:1.57

WORKDIR /cachepot

ADD ./src src
ADD ./tests tests
ADD Cargo.toml Cargo.lock ./

# RUN apt-get update && \
# 	apt-get install -y curl

RUN cargo build --all-targets --all-features

CMD [ "cargo", "test", "--locked", "--all-targets", "--no-default-features", "--features=dist-tests", "test_dist_" ]