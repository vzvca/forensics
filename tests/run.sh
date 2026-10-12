#!/bin/sh
# Test suite for symfind.
#
# Builds:
#   - a shared library exporting `dep_only_func` (defined only there)
#   - an executable linked against it and exporting `local_only_func`
#     via -rdynamic (defined in the executable itself)
#
# Then checks that symfind reports the right defining object in both cases.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0

check()
{
    desc="$1"
    expected="$2"
    input="$3"
    symbol="$4"

    got="$("$ROOT/symfind" "$input" "$symbol" 2>/dev/null)"
    if [ "$got" = "$expected" ]; then
        echo "ok: $desc"
    else
        echo "FAIL: $desc"
        echo "  expected: $expected"
        echo "  got:      ${got:-<no output>}"
        fail=1
    fi
}

make -C "$ROOT" >/dev/null || { echo "FAIL: build"; exit 1; }

# Build the test fixtures.
cat > "$TMP/dep.c" <<'EOF'
int dep_only_func(void)
{
    return 42;
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

# Case 1: symbol defined directly in the analyzed binary (not in a dependency).
check "symbol defined in the binary itself" \
     "$TMP/testbin" \
     "$TMP/testbin" \
     local_only_func

# Case 2: symbol defined in a direct dependency.
check "symbol defined in a dependency" \
     "$TMP/libtestdep.so" \
     "$TMP/testbin" \
     dep_only_func

# Case 3: a symbol that exists nowhere in the closure.
out="$("$ROOT/symfind" "$TMP/testbin" symbol_that_exists_nowhere 2>/dev/null)"
rc=$?
if [ $rc -eq 1 ]; then
    echo "ok: missing symbol reported not found"
else
    echo "FAIL: missing symbol should give rc=1, got rc=$rc, output: ${out:-<none>}"
    fail=1
fi

if [ $fail -eq 0 ]; then
    echo "all tests passed"
else
    echo "tests failed"
fi
exit $fail
