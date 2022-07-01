#!/bin/bash

cargo test --no-default-features --features="dist-tests" test_dist_ -- --test-threads 1