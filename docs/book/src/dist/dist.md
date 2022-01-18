# Distributed cachepot

Background:

- You should read about JSON Web Tokens - https://jwt.io/.
   - HS256 in short: you can sign a piece of (typically unencrypted)
     data with a key. Verification involves signing the data again
     with the same key and comparing the result. As a result, if you
     want two parties to verify each others messages, the key must be
     shared beforehand.
- 'secure token's referenced below should be generated with a CSPRNG
  (your OS random number generator should suffice).
  For example, on Linux this is accessible with: `openssl rand -hex 64`.
- When relying on random number generators (for generating keys or
  tokens), be aware that a lack of entropy is possible in cloud or
  virtualized environments in some scenarios.

## Overview

Distributed cachepot consists of three parts:

- the client, an cachepot binary that wishes to perform a compilation on
  remote machines
- the scheduler (`cachepot-dist` binary), responsible for deciding where
  a compilation job should run
- the worker (`cachepot-dist` binary), responsible for actually executing
  a build

All workers are required to be a 64-bit Linux install. Clients may request
compilation from Linux, Windows or macOS. Linux compilations will attempt to
automatically package the compiler in use, while Windows and macOS users will
need to specify a toolchain for cross-compilation ahead of time.

## Communication

The HTTP implementation of cachepot has the following API, where all HTTP body content is encoded using [`bincode`](http://docs.rs/bincode):

- `scheduler`
  - `POST /api/v1/scheduler/alloc_job`
    - Called by the coordinator to submit a compilation request.
    - Returns information on where the job is allocated it should run.
  - `GET /api/v1/scheduler/worker_certificate`
    - Called by the coordinator to retrieve the (dynamically created) HTTPS
       certificate for a worker, for use in communication with that worker.
    - Returns a digest and PEM for the temporary worker HTTPS certificate.
  - `POST /api/v1/scheduler/heartbeat_worker`
    - Called (repeatedly) by workers to register as available for jobs.
  - `POST /api/v1/scheduler/job_state`
    - Called by workers to inform the scheduler of the state of the job.
  - `GET /api/v1/scheduler/status`
    - Returns information about the scheduler.
- `worker`
  - `POST /api/v1/distworker/assign_job`
    - Called by the scheduler to inform of a new job being assigned to this worker.
    - Returns whether the toolchain is already on the worker or needs submitting.
  - `POST /api/v1/distworker/submit_toolchain`
    - Called by the coordinator to submit a toolchain.
  - `POST /api/v1/distworker/run_job`
    - Called by the coordinator to run a job.
    - Returns the compilation stdout along with files created.

There are three axes of security in this setup:

1. Can the scheduler trust the workers?
2. Is the coordinator permitted to submit and run jobs?
3. Can third parties see and/or modify traffic?

### Worker Trust

If a worker is malicious, they can return malicious compilation output to a user.
To protect against this, workers must be authenticated to the scheduler. You have three
means for doing this, and the scheduler and all workers must use the same mechanism.

Once a worker has registered itself using the selected authentication, the scheduler
will trust the registered worker address and use it for builds.

#### JWT HS256 (preferred)

This method uses secret key to create a per-IP-and-port token for each worker.
Acquiring a token will only allow participation as a worker if the attacker can
additionally impersonate the IP and port the token was generated for.

You *must* keep the secret key safe.

*To use it*:

Create a scheduler key with `cachepot-dist auth generate-jwt-hs256-key` (which will
use your OS random number generator) and put it in your scheduler config file as
follows:

```toml
worker_auth = { type = "jwt_hs256", secret_key = "YOUR_KEY_HERE" }
```

Now generate a token for the worker, giving the IP and port the scheduler and coordinator can
connect to the worker on (address `192.168.1.10:10501` here):

```sh
cachepot-dist auth generate-jwt-hs256-worker-token \
    --secret-key YOUR_KEY_HERE \
    --worker 192.168.1.10:10501
```

*or:*

```sh
cachepot-dist auth generate-jwt-hs256-worker-token \
    --config /path/to/scheduler-config.toml \
    --worker 192.168.1.10:10501
```

This will output a token (you can examine it with https://jwt.io if you're
curious) that you should add to your worker config file as follows:

```toml
scheduler_auth = { type = "jwt_token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Token

This method simply shares a token between the scheduler and all workers. A token
leak from anywhere allows any attacker to participate as a worker.

*To use it*:

Choose a 'secure token' you can share between your scheduler and all workers.

Put the following in your scheduler config file:

```toml
worker_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Put the following in your worker config file:

```toml
scheduler_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Insecure (bad idea)

*This route is not recommended*

This method uses a hardcoded token that effectively disables authentication and
provides no security at all.

*To use it*:

Put the following in your scheduler config file:

```toml
worker_auth = { type = "DANGEROUSLY_INSECURE" }
```

Put the following in your worker config file:

```toml
scheduler_auth = { type = "DANGEROUSLY_INSECURE" }
```

Done!

### Coordinator Trust

If a client is malicious, they can cause a DoS of distributed cachepot workers or
explore ways to escape the build sandbox. To protect against this, clients must
be authenticated.

Each client will use an authentication token for the initial job allocation request
to the scheduler. A successful allocation will return a job token that is used
to authorise requests to the appropriate worker for that specific job.

This job token is a JWT HS256 token of the job id, signed with a worker key.
The key for each worker is randomly generated on worker startup and given to
the scheduler during registration. This means that the worker can verify users
without either a) adding coordinator authentication to every worker or b) needing
secret transfer between scheduler and worker on every job allocation.

#### OAuth2

This is a group of similar methods for achieving the same thing - the coordinator
retrieves a token from an OAuth2 service, and then submits it to the scheduler
which has a few different options for performing validation on that token.

*To use it*:

Put one of the following settings in your scheduler config file to determine how
the scheduler will validate tokens from the client:

```toml
# Use the known settings for Mozilla OAuth2 token validation
client_auth = { type = "mozilla" }

# Will forward the valid JWT token onto another URL in the `Bearer` header, with a
# success response indicating the token is valid. Optional `cache_secs` how long
# to cache successful authentication for.
client_auth = { type = "proxy_token", url = "...", cache_secs = 60 }
```

Additionally, each client should set up an OAuth2 configuration in the with one of
the following settings (as appropriate for your OAuth service):

```toml
# Use the known settings for Mozilla OAuth2 authentication
auth = { type = "mozilla" }

# Use the Authorization Code with PKCE flow. This requires a client id,
# an initial authorize URL (which may have parameters like 'audience' depending
# on your service) and the URL for retrieving a token after the browser flow.
auth = { type = "oauth2_code_grant_pkce", client_id = "...", auth_url = "...", token_url = "..." }

# Use the Implicit flow (typically not recommended due to security issues). This requires
# a client id and an authorize URL (which may have parameters like 'audience' depending
# on your service).
auth = { type = "oauth2_implicit", client_id = "...", auth_url = "..." }
```

The client should then run `cachepot --dist-auth` and follow the instructions to retrieve
a token. This will be automatically cached locally for the token expiry period (manual
revalidation will be necessary after expiry).

#### Token

This method simply shares a token between the scheduler and all clients. A token
leak from anywhere allows any attacker to participate as a client.

*To use it*:

Choose a 'secure token' you can share between your scheduler and all clients.

Put the following in your scheduler config file:

```toml
client_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Put the following in your client config file:

```toml
auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Insecure (bad idea, again)

*This route is not recommended*

This method uses a hardcoded token that effectively disables authentication and
provides no security at all.

*To use it*:

Put the following in your scheduler config file:

```toml
client_auth = { type = "DANGEROUSLY_INSECURE" }
```

Remove any `auth =` setting under the `[dist]` heading in your client config file
(it will default to this insecure mode).

Done!

### Eavesdropping and Tampering Protection

If third parties can see traffic to the workers, source code can be leaked. If third
parties can modify traffic to and from the workers or the scheduler, they can cause
the client to receive malicious compiled objects.

Securing communication with the scheduler is the responsibility of the cachepot cluster
administrator - it is recommended to put a webworker with a HTTPS certificate in front
of the scheduler and instruct clients to configure their `scheduler_url` with the
appropriate `https://` address. The scheduler will verify the worker's IP in this
configuration by inspecting the `X-Real-IP` header's value, if present. The webworker
used in this case should be configured to set this header to the appropriate value.

Securing communication with the worker is performed automatically - HTTPS certificates
are generated dynamically on worker startup and communicated to the scheduler during
the heartbeat. If a client does not have the appropriate certificate for communicating
securely with a worker (after receiving a job allocation from the scheduler), the
certificate will be requested from the scheduler.

# Building the Distributed Worker Binaries

Until these binaries [are included in releases](https://github.com/paritytech/cachepot/issues/393) I've put together a Docker container that can be used to easily build a release binary:

```toml
docker run -ti --rm -v $PWD:/cachepot luser/cachepot-musl-build:0.1 /bin/bash -c "cd /cachepot; cargo build --release --target x86_64-unknown-linux-musl --features=dist-worker && strip target/x86_64-unknown-linux-musl/release/cachepot-dist && cd target/x86_64-unknown-linux-musl/release/ && tar czf cachepot-dist.tar.gz cachepot-dist"
```
