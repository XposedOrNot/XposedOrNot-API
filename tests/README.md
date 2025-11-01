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

### Domain Validation (`test_fuzz_domain_validation.py`)
- Tests `validate_domain()` with random text inputs
- Tests `is_safe_domain()` to prevent SSRF attacks
- Verifies private/internal IP blocking
- Validates public domain allowance

### General Validation (`test_fuzz_validation.py`)
- Tests `validate_email_with_tld()` with various email formats
- Tests `validate_variables()` with mixed input types
- Edge case handling for empty/null inputs

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
