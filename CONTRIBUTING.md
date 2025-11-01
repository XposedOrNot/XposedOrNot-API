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

### 1. Before You Start
- **Discuss first**: For significant changes, open an issue or discussion before starting work
- **One PR, one purpose**: Keep pull requests focused on a single feature or fix
- **Check existing PRs**: Make sure someone isn't already working on the same thing

### 2. Creating Your Branch
```bash
# Update your local master branch
git checkout master
git pull origin master

# Create a new feature branch with descriptive name
git checkout -b feature/your-feature-name
# OR for bug fixes
git checkout -b fix/issue-description
```

### 3. Making Changes
- Write clear, concise commit messages (see Git Commit section below)
- Follow the Style Guide (PEP-8 for Python code)
- Include tests for new functionality
- Update documentation (README.md, docstrings, etc.) as needed
- Add source headers to any new files

### 4. Before Submitting
Run local checks to ensure your PR will pass CI:
```bash
# Run code formatting
black .

# Run linting
pylint --fail-under=8 $(git ls-files '*.py')

# Run tests (if applicable)
pytest
```

### 5. Submitting Your Pull Request
```bash
# Push your branch to GitHub
git push origin feature/your-feature-name

# Create PR via GitHub web interface or CLI
gh pr create --title "Description of changes" --body "Detailed explanation"
```

**PR Title Format**: Use conventional commit prefixes (🐛 fix:, ✨ feat:, etc.)

**PR Description Should Include**:
- **Summary**: Brief overview of changes
- **Motivation**: Why is this change needed?
- **Changes**: List of specific modifications
- **Testing**: How was this tested?
- **Screenshots**: If applicable (UI changes)

### 6. Code Review Process
All pull requests require:
- ✅ **Code review approval** from at least one maintainer
- ✅ **All CI checks passing** (Black, Pylint, CodeQL, Scorecard)
- ✅ **Signed commits** (required by branch protection)
- ✅ **No merge conflicts** with master branch

**What happens during review:**
1. Automated checks run (linting, formatting, security scans)
2. Reviewer examines code for quality, security, and best practices
3. Reviewer may request changes or ask questions
4. You address feedback by pushing additional commits
5. Once approved and all checks pass, a maintainer will merge

### 7. Addressing Review Feedback
```bash
# Make requested changes on your branch
git add .
git commit -m "Address review feedback"
git push origin feature/your-feature-name
```

The PR will automatically update with your new commits.

### 8. After Your PR is Merged
```bash
# Update your local master branch
git checkout master
git pull origin master

# Delete your feature branch
git branch -d feature/your-feature-name
git push origin --delete feature/your-feature-name
```

### Pull Request Checklist
Before submitting, ensure:
- [ ] Code follows PEP-8 style guidelines
- [ ] All tests pass locally
- [ ] Documentation updated (if needed)
- [ ] Commits are signed
- [ ] PR description is clear and complete
- [ ] No sensitive data (credentials, keys) in code
- [ ] Branch is up to date with master

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

