#!/bin/sh
# Test suite for symfind and symtrace.
#
# symfind: builds a shared library and an -rdynamic executable linking it,
# then checks exact, glob and regex matching, plus the not-found case.
#
# symtrace: builds a victim that calls fopen() in a loop, attaches to it
# by PID and checks that the call count matches.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [ -n "${VICTIM_PID:-}" ] && kill "$VICTIM_PID" 2>/dev/null' EXIT

fail=0

check()
{
    desc="$1"
    expected="$2"
    shift 2

    got="$("$ROOT/symfind" "$@" 2>/dev/null | sort)"
    if [ "$got" = "$expected" ]; then
        echo "ok: $desc"
    else
        echo "FAIL: $desc"
        echo "  expected: $expected"
        echo "  got:      ${got:-<no output>}"
        fail=1
    fi
}

check_rc()
{
    desc="$1"
    expected_rc="$2"
    shift 2

    "$ROOT/symfind" "$@" >/dev/null 2>&1
    rc=$?
    if [ "$rc" = "$expected_rc" ]; then
        echo "ok: $desc"
    else
        echo "FAIL: $desc"
        echo "  expected rc: $expected_rc"
        echo "  got rc:      $rc"
        fail=1
    fi
}

make -C "$ROOT" >/dev/null || { echo "FAIL: build"; exit 1; }

# ---------- symfind ----------

cat > "$TMP/dep.c" <<'EOF'
int dep_only_func(void)
{
    return 42;
}

int dep_wild_func_1(void)
{
    return 1;
}

int dep_wild_func_2(void)
{
    return 2;
}
EOF

cat > "$TMP/main.c" <<'EOF'
extern int dep_only_func(void);

int local_only_func(void)
{
    return dep_only_func() + 1;
}

int main(void)
{
    return local_only_func();
}
EOF

gcc -shared -fPIC -o "$TMP/libtestdep.so" "$TMP/dep.c" || { echo "FAIL: build fixture"; exit 1; }
gcc -o "$TMP/testbin" "$TMP/main.c" -L"$TMP" -ltestdep -Wl,-rpath,"$TMP" -rdynamic || { echo "FAIL: build fixture"; exit 1; }

check "exact: symbol defined in the binary itself" \
     "$TMP/testbin: local_only_func" \
     "$TMP/testbin" local_only_func

check "exact: symbol defined in a dependency" \
     "$TMP/libtestdep.so: dep_only_func" \
     "$TMP/testbin" dep_only_func

check "glob: multiple symbols in a dependency" \
     "$TMP/libtestdep.so: dep_wild_func_1
$TMP/libtestdep.so: dep_wild_func_2" \
     -g "$TMP/testbin" 'dep_wild_*'

check "regex: symbol in the binary itself" \
     "$TMP/testbin: local_only_func" \
     -r "$TMP/testbin" '^local_[a-z_]+$'

check "regex: symbols in a dependency" \
     "$TMP/libtestdep.so: dep_only_func
$TMP/libtestdep.so: dep_wild_func_1
$TMP/libtestdep.so: dep_wild_func_2" \
     -r "$TMP/testbin" '^dep_(only|wild)_'

check_rc "missing symbol reported not found" 1 "$TMP/testbin" symbol_that_exists_nowhere

check_rc "invalid regex reported" 2 -r "$TMP/testbin" '['

# ---------- symtrace (launch mode) ----------

cat > "$TMP/spawn.c" <<'SPAWNEOF'
#include <stdio.h>
int main(void)
{
    FILE *f = fopen("/etc/hostname", "r");
    if (f)
        fclose(f);
    f = fopen("/etc/hostname", "r");
    if (f)
        fclose(f);
    return 0;
}
SPAWNEOF

gcc -O0 -o "$TMP/spawn" "$TMP/spawn.c" || { echo "FAIL: build spawn"; exit 1; }

"$ROOT/symtrace" -r fopen -- "$TMP/spawn" > "$TMP/spawn.out" 2>&1
rc=$?
if [ "$rc" = "0" ] && grep -q 'fopen("/etc/hostname", "r") = ' "$TMP/spawn.out" \
   && grep -q '2 calls intercepted' "$TMP/spawn.out"; then
    echo "ok: symtrace launch mode traced calls from process start"
else
    echo "FAIL: symtrace launch mode (rc=$rc)"
    cat "$TMP/spawn.out"
    fail=1
fi

# ---------- symtrace (attach mode) ----------

cat > "$TMP/victim.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    /* one call before the tracer attaches */
    FILE *f = fopen("/etc/hostname", "r");
    if (f)
        fclose(f);
    for (int i = 0; i < 10; i++) {
        sleep(1);
        f = fopen("/etc/hostname", "r");
        if (f)
            fclose(f);
    }
    return 0;
}
EOF

gcc -O0 -o "$TMP/victim" "$TMP/victim.c" || { echo "FAIL: build victim"; exit 1; }

"$TMP/victim" >/dev/null 2>&1 &
VICTIM_PID=$!
sleep 1

"$ROOT/symtrace" "$VICTIM_PID" fopen > "$TMP/trace.out" 2>&1 &
TRACE_PID=$!
sleep 3
kill -INT "$TRACE_PID"
wait "$TRACE_PID"
kill "$VICTIM_PID" 2>/dev/null
wait "$VICTIM_PID" 2>/dev/null
VICTIM_PID=""

count="$(sed -n 's/^fopen: \([0-9]*\) call.*$/\1/p' "$TMP/trace.out" | tr -d '\r')"
if grep -q 'fopen("/etc/hostname", "r") = ' "$TMP/trace.out"; then
    echo "ok: symtrace decoded fopen arguments and return value"
else
    echo "FAIL: symtrace did not decode fopen arguments and return value"
    cat "$TMP/trace.out"
    fail=1
fi
# victim calls fopen once per second after the first; tracer attached at ~1s,
# traced for ~3s so expect 2-3 calls. Accept 1..4 to stay robust.
if [ -n "$count" ] && [ "$count" -ge 1 ] && [ "$count" -le 4 ]; then
    echo "ok: symtrace counted $count fopen calls"
else
    echo "FAIL: symtrace call count (got '${count:-none}', expected 1..4)"
    cat "$TMP/trace.out"
    fail=1
fi

if [ $fail -eq 0 ]; then
    echo "all tests passed"
else
    echo "tests failed"
fi
exit $fail
