# Unearth Forensic Recovery Tool - Makefile
# Simplifies common development and deployment tasks

.PHONY: help install install-dev install-minimal run run-gui run-cli test clean uninstall

# Default target
help:
	@echo ""
	@echo "Unearth Forensic Recovery Tool - Available Commands"
	@echo "===================================================="
	@echo ""
	@echo "Installation:"
	@echo "  make install          Install with all dependencies"
	@echo "  make install-dev      Install with development tools"
	@echo "  make install-minimal  Install minimal dependencies only"
	@echo ""
	@echo "Running:"
	@echo "  make run              Run interactive mode"
	@echo "  make run-gui          Run GUI directly"
	@echo "  make run-cli          Run CLI directly"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run test suite"
	@echo "  make test-coverage    Run tests with coverage report"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean            Clean build artifacts"
	@echo "  make uninstall        Uninstall Unearth"
	@echo "  make update           Update to latest version"
	@echo ""
	@echo "Packaging:"
	@echo "  make build            Build distribution packages"
	@echo "  make deploy           Deploy to PyPI (maintainers only)"
	@echo ""

# Installation targets
install:
	@echo "Installing Unearth with all dependencies..."
	pip install -e .
	@echo "✓ Installation complete!"
	@echo ""
	@echo "Run with: python run.py"
	@echo "Or: make run"

install-dev:
	@echo "Installing Unearth with development dependencies..."
	pip install -e ".[dev]"
	@echo "✓ Development installation complete!"

install-minimal:
	@echo "Installing Unearth with minimal dependencies..."
	pip install -e ".[minimal]"
	@echo "✓ Minimal installation complete!"

# Running targets
run:
	@python run.py

run-gui:
	@python run.py --gui

run-cli:
	@python run.py --cli

# Testing targets
test:
	@echo "Running test suite..."
	pytest tests/ -v

test-coverage:
	@echo "Running tests with coverage..."
	pytest tests/ --cov=src --cov-report=html --cov-report=term
	@echo ""
	@echo "Coverage report generated in htmlcov/index.html"

# Maintenance targets
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "✓ Cleanup complete!"

uninstall:
	@echo "Uninstalling Unearth..."
	pip uninstall -y Unearth-forensics
	@echo "✓ Uninstall complete!"

update:
	@echo "Updating Unearth..."
	git pull origin main
	pip install -e . --upgrade
	@echo "✓ Update complete!"

# Packaging targets
build:
	@echo "Building distribution packages..."
	python -m build
	@echo "✓ Build complete! Packages in dist/"

deploy:
	@echo "Deploying to PyPI..."
	@echo "Warning: This requires PyPI credentials"
	twine upload dist/*

# Development helpers
format:
	@echo "Formatting code with black..."
	black src/ tests/
	@echo "✓ Formatting complete!"

lint:
	@echo "Linting code..."
	flake8 src/ tests/
	@echo "✓ Linting complete!"

type-check:
	@echo "Type checking with mypy..."
	mypy src/
	@echo "✓ Type checking complete!"

# Setup virtual environment
venv:
	@echo "Creating virtual environment..."
	python3 -m venv venv
	@echo "✓ Virtual environment created!"
	@echo ""
	@echo "Activate with:"
	@echo "  source venv/bin/activate  (Linux/Mac)"
	@echo "  venv\\Scripts\\activate    (Windows)"

# Quick setup for new contributors
setup:
	@echo "Setting up development environment..."
	python3 -m venv venv
	. venv/bin/activate && pip install -e ".[dev]"
	@echo "✓ Development environment ready!"
	@echo ""
	@echo "Activate with: source venv/bin/activate"

# Database creation (for future features)
init-db:
	@echo "Initializing database..."
	python -c "from src.app import UnearthApp; app = UnearthApp(); print('Database initialized')"

# Generate documentation
docs:
	@echo "Generating documentation..."
	cd docs && make html
	@echo "✓ Documentation generated in docs/_build/html/"

# Show project statistics
stats:
	@echo "Project Statistics"
	@echo "=================="
	@echo ""
	@echo "Python files:"
	@find src/ -name "*.py" | wc -l
	@echo ""
	@echo "Lines of code:"
	@find src/ -name "*.py" -exec wc -l {} + | tail -1
	@echo ""
	@echo "Test files:"
	@find tests/ -name "test_*.py" 2>/dev/null | wc -l || echo "0"