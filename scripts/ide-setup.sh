#!/usr/bin/env bash
# Editor support on macOS. The engine is Linux code (kernel netfilter headers,
# libnetfilter_queue), so a Mac's own headers can't check it. This copies the
# headers out of the Docker build image into .sysroot/ and writes
# compile_commands.json, so VS Code (C/C++ or clangd) analyses the code as
# Linux, exactly like the real build. Both outputs are git-ignored.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

docker build -q --target build -f docker/firewall.Dockerfile -t gatekeep-build . >/dev/null
ARCH=$(docker run --rm gatekeep-build uname -m)
TRIPLE="$ARCH-linux-gnu"

rm -rf .sysroot && mkdir -p .sysroot/usr/lib
container=$(docker create gatekeep-build)
docker cp -q "$container:/usr/include" .sysroot/usr/include
docker cp -q "$container:/usr/local/include/httplib.h" .sysroot/usr/include/httplib.h
# clang finds the libstdc++ headers through the GCC install directory.
docker cp -q "$container:/usr/lib/gcc" .sysroot/usr/lib/gcc
docker rm "$container" >/dev/null
find .sysroot/usr/lib/gcc -type f ! -name 'crt*.o' ! -path '*/include/*' -delete

FLAGS="--target=$TRIPLE --sysroot=$ROOT/.sysroot -std=c++17 -Wall -Wextra -I$ROOT/engine/src"
{
    echo "["
    first=1
    for f in engine/src/*.cpp engine/tests/*.cpp; do
        [ $first -eq 1 ] || echo ","
        first=0
        printf '  {"directory": "%s", "file": "%s", "command": "clang++ %s -c %s"}' "$ROOT" "$ROOT/$f" "$FLAGS" "$ROOT/$f"
    done
    echo
    echo "]"
} > compile_commands.json

echo "Checking every source file against the Linux headers..."
for f in engine/src/*.cpp engine/tests/*.cpp; do
    clang++ $FLAGS -fsyntax-only "$f"
done
echo "OK: .sysroot/ and compile_commands.json ready ($TRIPLE). Reload the VS Code window."
