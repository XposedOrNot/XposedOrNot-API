# Contributing to This Repository

## Scope

This document provides guidelines for contributing to this repository.

## Issues

File an issue if you think you've found a bug. Please describe:

1. How can it be reproduced
2. What was expected
3. What actually occurred
4. What version of the involved component was used

## Patches

All contributions are welcome and most will be accepted. Patches for fixes, features, and improvements are accepted via pull requests.

Pull requests should be based on the master branch, unless you want to contribute to an active branch for a specific topic.

When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change. 

## Pull Request Process

1. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations and container parameters.
2. To contribute, just issue a pull request. Include tests, please. If you add any new files please make sure you add the source header to the top of that file.
3. Commit messages should explain why code is changing, configuration is added, or new types or packages are introduced.

## Style Guide

- Functions should take as few parameters as possible. If many parameters are required, consider introducing a new type that logically groups the data.
- Large blocks of commented out code should not be checked in.
- Avoid the use of global variables. Prefer a dependency injection style that uses a mix of interfaces and concrete types.
- Follow Python styling guidelines including PEP-8 for code.

## Git Commit

Use these prefixes when committing:

- 🐛 fix: Corrected typo in README.md
- ✨ feat: Added user login functionality
- 📝 docs: Updated API documentation
- 💄 style: Improved button UI in the header
- ♻️ refactor: Refactored alertme processing code
- ✅ test: Added unit tests for new utility functions
- 🧹 chore: Removed unused dependencies from package.json
- ⚡ perf: Optimized database query performance

