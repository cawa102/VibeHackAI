# Contributing to PentestAgent

Thank you for your interest in contributing to PentestAgent! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow ethical security practices

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- Node.js 18+ (for MCP servers)
- Understanding of penetration testing concepts

### Finding Issues

- Check [Issues](https://github.com/cawa102/VibeHackAI/issues) for open tasks
- Look for `good first issue` labels for beginner-friendly tasks
- Check `help wanted` labels for tasks needing assistance

## Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/PentestAgent.git
cd PentestAgent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install

# Run tests to verify setup
pytest
```

## Development Workflow

### Specification-First Development

This project follows a **specification-first** approach:

1. Specifications in `docs/` are the source of truth
2. Code must follow specifications
3. If specifications need changes, update them first via PR

### Branch Naming

```
feature/short-description  - New features
fix/issue-number-short-description  - Bug fixes
docs/short-description  - Documentation updates
refactor/short-description  - Code refactoring
```

### Commit Messages

Follow conventional commit format:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

### Example Workflow

```bash
# Create feature branch
git checkout -b feature/add-new-mcp-adapter

# Make changes
# ... edit files ...

# Run tests
pytest

# Run linting
ruff check src/
black src/ --check
mypy src/

# Commit changes
git add .
git commit -m "feat(mcp): add new adapter for tool X"

# Push and create PR
git push origin feature/add-new-mcp-adapter
```

## Code Standards

### Python Style

- Follow PEP 8
- Use type hints for all functions
- Maximum line length: 88 characters (Black default)
- Use meaningful variable and function names

### Tools

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

### Code Organization

```
src/
├── agents/         # Agent implementations
├── orchestrator/   # Control plane
├── cli/            # CLI interface
├── storage/        # State and evidence
├── mcp_adapters/   # MCP integrations
├── passer/         # Data normalization
├── patch/          # Patch protocol
└── schemas/        # Schema definitions
```

### Key Principles

1. **Single Responsibility**: Each module has one clear purpose
2. **Idempotency**: Same input should produce same output
3. **Fail-Fast**: Validate preconditions early
4. **Least Privilege**: Components access only what they need

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_agents.py

# Run specific test
pytest tests/test_agents.py::test_reconnaissance_agent

# Verbose output
pytest -v
```

### Writing Tests

- Place tests in `tests/` directory
- Follow naming convention: `test_*.py`
- Use fixtures from `tests/fixtures/`
- Test both success and failure cases

```python
# Example test
def test_agent_validates_scope():
    """Agent should reject out-of-scope targets."""
    agent = ReconnaissanceAgent()
    context = create_context(targets=["out-of-scope.com"])

    result = agent.run(context)

    assert not result.success
    assert "scope" in result.error.lower()
```

### Test Categories

- **Unit tests**: Test individual components
- **Integration tests**: Test component interactions
- **Fixture-based**: Use realistic test data

## Pull Request Process

### Before Submitting

1. Ensure all tests pass: `pytest`
2. Run linting: `ruff check src/`
3. Format code: `black src/`
4. Update documentation if needed
5. Add tests for new features

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] All tests pass
- [ ] Added new tests for changes
- [ ] Tested manually

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Updated documentation
- [ ] No breaking changes (or documented)
```

### Review Process

1. Submit PR with clear description
2. Wait for CI checks to pass
3. Address reviewer feedback
4. Maintainer merges after approval

## Documentation

### Types of Documentation

1. **Code comments**: Explain "why", not "what"
2. **Docstrings**: Document public APIs
3. **Specs (`docs/`)**: Detailed specifications
4. **README/guides**: User-facing documentation

### Docstring Format

```python
def process_target(target: str, options: dict) -> Result:
    """Process a target for reconnaissance.

    Args:
        target: IP address or domain name
        options: Processing options including timeout and depth

    Returns:
        Result object with findings and evidence

    Raises:
        ScopeError: If target is out of scope
        TimeoutError: If processing exceeds timeout
    """
```

### Updating Specifications

If your change affects behavior documented in `docs/`:

1. Update the relevant spec file first
2. Get spec changes reviewed
3. Implement code changes
4. Ensure code matches spec

## Adding New Components

### New MCP Adapter

1. Create `src/mcp_adapters/new_adapter.py`
2. Extend `BaseAdapter`
3. Create corresponding passer in `src/passer/`
4. Add tests in `tests/`
5. Update `.mcp.json` example
6. Document in `INSTALLATION.md`

### New Agent

1. Read existing agent specs in `docs/`
2. Create spec document first
3. Implement in `src/agents/`
4. Define MCP usage policy
5. Add comprehensive tests
6. Update documentation

## Questions?

- Open an issue for questions
- Check existing issues and docs first
- Be specific about your question

Thank you for contributing!
