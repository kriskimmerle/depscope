# Contributing to depscope

Thanks for your interest in contributing!

## Quick Start

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/depscope`
3. Install: `pip install -e .`
4. Make changes
5. Test: Run `depscope` on sample requirements files
6. Push and open a PR

## What to Contribute

- Support for additional package managers (npm, cargo, go modules, etc.)
- Improved dependency tree visualization
- Circular dependency detection
- License compliance checking
- Security vulnerability scanning
- Size/bloat analysis
- Unused dependency detection

## Code Style

- Python 3.7+ compatible
- Keep dependencies minimal
- Clear variable names
- Efficient graph algorithms

## Testing

Test with various dependency structures:
- Simple linear dependencies
- Complex transitive dependencies
- Circular dependencies
- Large dependency trees (performance testing)

## Reporting Issues

Open an issue with:
- Package manager you're using
- Sample dependency file (if applicable)
- Expected vs. actual behavior

## Ideas for Contributions

- Interactive tree navigation (collapse/expand)
- Export to DOT/GraphViz format
- Dependency update impact analysis
- Integration with dependency vulnerability databases
- Comparison mode (show what changed between versions)
- Dependency pruning suggestions
- Platform-specific dependency handling

## License

By contributing, you agree your contributions will be licensed under MIT.
