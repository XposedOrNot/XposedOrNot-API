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
- Tests `is_valid_domain_name()` wrapper function
- Tests domain validation with unicode and special characters
- Validates handling of wrong input types
- Edge case handling for malformed domains
- Over 500 test cases via property-based testing

## Benefits for Security

These fuzzing tests help:
- **Prevent crashes** from unexpected inputs
- **Discover security vulnerabilities** (injection attacks, malformed input)
- **Improve OSSF Scorecard** fuzzing score
- **Ensure robustness** of validation functions
- **Catch edge cases** that manual testing might miss

## Scope

These tests focus **only on pure utility functions** from `utils/helpers.py`:
- No API routes
- No database connections
- No environment variables
- No external services

This ensures tests run successfully in CI/CD without Docker or Cloud dependencies.

## CI/CD Integration

Fuzzing tests run automatically:
- On every push to master
- On every pull request
- Weekly on Mondays at 2 AM UTC
