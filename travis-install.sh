#!/bin/bash
curl -sL https://github.com/xd009642/tarpaulin/releases/download/0.6.9/cargo-tarpaulin-0.6.9-travis.tar.gz | tar xvz -C $HOME/.cargo/bin
echo "WARNING This method is no longer recommended. Use docker or crates.io to install tarpaulin"
