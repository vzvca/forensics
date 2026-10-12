#!/bin/sh
# Test suite for symfind.
#
# Builds:
#   - a shared library exporting `dep_only_func` and `dep_wild_func_1`
#     (defined only there)
#   - an executable linked against it and exporting `local_only_func`
#     via -rdynamic (defined in the executable itself)
#
# Then checks exact, glob and regex matching, plus the not-found case.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

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

# Build the test fixtures.
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

# Case 1: symbol defined directly in the analyzed binary (not in a dependency).
check "exact: symbol defined in the binary itself" \
     "$TMP/testbin: local_only_func" \
     "$TMP/testbin" local_only_func

# Case 2: symbol defined in a direct dependency.
check "exact: symbol defined in a dependency" \
     "$TMP/libtestdep.so: dep_only_func" \
     "$TMP/testbin" dep_only_func

# Case 3: glob matching several symbols in a dependency.
check "glob: multiple symbols in a dependency" \
     "$TMP/libtestdep.so: dep_wild_func_1
$TMP/libtestdep.so: dep_wild_func_2" \
     -g "$TMP/testbin" 'dep_wild_*'

# Case 4: regex matching symbols across the binary and its dependencies.
check "regex: symbol in the binary itself" \
     "$TMP/testbin: local_only_func" \
     -r "$TMP/testbin" '^local_[a-z_]+$'

check "regex: symbols in a dependency" \
     "$TMP/libtestdep.so: dep_only_func
$TMP/libtestdep.so: dep_wild_func_1
$TMP/libtestdep.so: dep_wild_func_2" \
     -r "$TMP/testbin" '^dep_(only|wild)_'

# Case 5: a symbol that exists nowhere in the closure.
check_rc "missing symbol reported not found" 1 "$TMP/testbin" symbol_that_exists_nowhere

# Case 6: invalid regex is a usage error.
check_rc "invalid regex reported" 2 -r "$TMP/testbin" '['

if [ $fail -eq 0 ]; then
    echo "all tests passed"
else
    echo "tests failed"
fi
exit $fail
