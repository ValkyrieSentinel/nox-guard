#!/bin/bash
set -e

BINARY="./nox-core"

[ -f "$BINARY" ] || { echo "err: binary not found"; exit 1; }

# 1. No args -> expected failure
$BINARY >/dev/null 2>&1 && { echo "t1: fail"; exit 1; } || echo "t1: ok"

# 2. Valid ELF (/bin/ls)
$BINARY /bin/ls | grep -q "valid, uncompromised" && echo "t2: ok" || { echo "t2: fail"; exit 1; }

# 3. Non-existent path -> expected failure
$BINARY /non/existent/path >/dev/null 2>&1 && { echo "t3: fail"; exit 1; } || echo "t3: ok"

# 4. Directory scan (/tmp)
$BINARY /tmp | grep -q "Directory contents" && echo "t4: ok" || { echo "t4: fail"; exit 1; }

# 5. Invalid ELF magic check
printf "\x7fFAKE" > /tmp/nox_bad_elf
$BINARY /tmp/nox_bad_elf | grep -q "uncompromised" && { rm -f /tmp/nox_bad_elf; echo "t5: fail"; exit 1; } || { rm -f /tmp/nox_bad_elf; echo "t5: ok"; }

echo "all passed"