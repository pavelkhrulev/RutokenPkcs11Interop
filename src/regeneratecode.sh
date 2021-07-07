#!/bin/bash

set -e

SLNDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd $SLNDIR/RutokenPkcs11Interop
./regeneratecode.sh

cd $SLNDIR/RutokenPkcs11Interop.Tests
./regeneratecode.sh
