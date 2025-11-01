# Fuzzing Tests

This directory contains property-based fuzzing tests using [Hypothesis](https://hypothesis.readthedocs.io/).

## What is Fuzzing?

Fuzzing is an automated testing technique that provides invalid, unexpected, or random data as inputs to functions to discover bugs, crashes, or security vulnerabilities.

## Running Tests

### Run all tests
```bash
pytest tests/
```

### Run only fuzzing tests
```bash
pytest tests/ -v
```

### Run with more examples (deeper fuzzing)
```bash
pytest tests/ --hypothesis-seed=random
```

## Test Coverage

### Helper Functions (`test_fuzz_helpers.py`)
- Tests `validate_domain()` with random text inputs
- Tests domain validation with unicode and special characters
- Validates handling of wrong input types
- Edge case handling for malformed domains

### SSRF Protection (`test_fuzz_ssrf_protection.py`)
- Tests `is_safe_domain()` to prevent SSRF attacks
- Verifies private/internal IP blocking (127.0.0.1, 192.168.x.x, 10.x.x.x)
- Validates public domain allowance
- Tests against cloud metadata endpoints (169.254.169.254)

## Benefits for Security

These fuzzing tests help:
- **Prevent crashes** from unexpected inputs
- **Discover security vulnerabilities** (like SSRF, injection attacks)
- **Improve OSSF Scorecard** fuzzing score
- **Ensure robustness** of validation functions
- **Catch edge cases** that manual testing might miss

## CI/CD Integration

Fuzzing tests run automatically:
- On every push to master
- On every pull request
- Weekly on Mondays at 2 AM UTC
