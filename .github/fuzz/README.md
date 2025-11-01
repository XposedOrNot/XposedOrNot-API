# Fuzzing with Atheris

This directory contains fuzzing harnesses for the API using [Atheris](https://github.com/google/atheris), a coverage-guided Python fuzzing engine based on libFuzzer.

## Fuzz Targets

### fuzz_validation.py
Fuzzes input validation functions:
- `validate_variables()` - Tests variable validation with various input patterns
- `validate_email_with_tld()` - Tests email validation logic
- `validate_token()` - Tests token format validation

### fuzz_helpers.py
Fuzzes helper utility functions:
- `validate_domain()` - Tests domain name validation
- `is_valid_domain_name()` - Tests domain name checking
- `is_valid_ip()` - Tests IP address validation
- `get_preferred_ip_address()` - Tests X-Forwarded-For parsing
- `generate_request_hash()` - Tests hash generation
- `string_to_boolean()` - Tests string to boolean conversion

## Running Locally

### Install Atheris

```bash
pip install atheris
```

### Run a specific fuzzer

```bash
# From the project root
cd .github/fuzz
python fuzz_validation.py
```

### Run with specific parameters

```bash
# Run for 100,000 iterations
python fuzz_validation.py -atheris_runs=100000

# Run for 60 seconds
timeout 60s python fuzz_validation.py
```

## CI/CD Integration

Fuzzing runs automatically on:
- Every push to master
- Every pull request
- Weekly schedule (Mondays at 2 AM UTC)
- Manual workflow dispatch

The CI runs each fuzzer for 60 seconds to catch crashes and assertion failures.

## Why These Functions?

These functions are fuzzed because they:
1. Handle untrusted user input
2. Are security-critical validation functions
3. Don't require external dependencies (database, APIs)
4. Can run in isolation in GitHub Actions

## What the Fuzzer Checks

The fuzzer looks for:
- Crashes and exceptions
- Assertion failures
- Type errors
- Unexpected behavior with malformed input
- Edge cases that manual testing might miss
