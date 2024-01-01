## Static analysis (MIRAI)

### Why: 
current static tool like clippy can't detect rust programs that terminate abruptly and disgracefully.

### MIRAI

https://github.com/facebookexperimental/MIRAI

MIRAI does this by doing a reachability analysis: Given an entry point, it will analyze all possible code paths that start from that entry point and determine if any of them can reach a program point where an abrupt runtime termination will happen. 

### How to use

#### Step 1: Install MIRAI

```
git clone https://github.com/facebookexperimental/MIRAI.git
cd MIRAI
git checkout c6c1a4f84c2b463c393761a8c60f6d084a11389b
cargo install --locked --path ./checker
```

Note: MIRAI required rust toolchain version: nightly-2022-08-08

#### Step 2: Scan your crate

Use td-shim as example

```
git clone https://github.com/confidential-containers/td-shim.git; cd td-shim
git checkout a0b51c0f7f4736c65de8a6eb9644e31e762df623
echo "nightly-2022-08-08" > rust-toolchain
cd td-shim
cargo mirai --features="main,tdx"
```

### Limitation

* MIRAI requires a specific rust toolchain.
* MIRAI needs to consume a lot of memory.(td-shim 32G+)
