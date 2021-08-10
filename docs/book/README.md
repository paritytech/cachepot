# cachepot distributed compilation quickstart

# Building

Before you can build and serve the book you need to install the dependencies. Run the command below to get them.

```sh
cargo install mdbook mdbook-linkcheck mdbook-mermaid
```

After they are successfully installed you can serve the book using

```sh
mdbook serve
```

which will be available on [http://127.0.0.1:3000](http://127.0.0.1:3000).

If you want to just build it use

```sh
mdbook build
```
