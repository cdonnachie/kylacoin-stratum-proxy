# Contributing to KCN Proxy

Thank you for your interest in contributing to the KCN Proxy project! We welcome contributions from the community and appreciate your help in making this project better.

## Getting Started

### Prerequisites

- Python 3.9+
- Docker and Docker Compose (for containerized development)
- Git

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/cdonnachie/kylacoin-stratum-proxy.git
   cd kylacoin-stratum-proxy
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure your environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run the proxy**
   ```bash
   python -m kcn_proxy.main
   ```

### Using Docker

```bash
docker-compose up -d
```

## Reporting Issues

### Bug Reports

Before creating a bug report, please check the existing issues to see if the problem has already been reported. When creating a bug report, include:

- **Descriptive title** - Clearly describe the issue
- **Steps to reproduce** - Exact steps to reproduce the problem
- **Expected behavior** - What you expected to happen
- **Actual behavior** - What actually happened
- **Environment** - OS, Python version, Docker version, etc.
- **Logs** - Relevant error messages or logs
- **Screenshots** - If applicable

### Feature Requests

Feature requests are welcome! Please include:

- **Clear description** - What you want to add and why
- **Use cases** - How this feature would be useful
- **Possible implementation** - Any suggestions on how to implement it (optional)

## Making Changes

### Branch Naming

- Feature: `feature/short-description`
- Bug fix: `bugfix/short-description`
- Documentation: `docs/short-description`

Example: `feature/add-worker-filter` or `bugfix/fix-api-route-matching`

### Commit Messages

Write clear, descriptive commit messages:

```
Add filter status indicator to shares dashboard

- Display active filters as individual badges
- Allow clearing individual filters
- Disable search field when specific worker selected
- Add animations for filter badge appearance
```

### Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and reasonably sized

### Testing

Before submitting a pull request:

1. **Syntax check** - Verify your Python code compiles
   ```bash
   python -m py_compile kcn_proxy/your_file.py
   ```

2. **Manual testing** - Test your changes thoroughly
   - For UI changes: Test in both dark and light modes
   - For API changes: Test affected endpoints
   - For database changes: Verify data integrity

3. **Browser compatibility** - Test UI changes in modern browsers

## Submitting Changes

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit with clear messages

3. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a Pull Request**
   - Provide a clear title and description
   - Reference related issues (e.g., "Fixes #123")
   - Describe what you changed and why
   - Include any relevant testing information

### PR Guidelines

- Keep PRs focused - one feature/fix per PR
- Update documentation if needed
- Add comments for complex logic
- Test across different browsers for UI changes
- Ensure all code follows the style guidelines

## Project Structure

```
kcn-proxy/
├── kcn_proxy/           # Main application code
│   ├── web/            # Web dashboard and API
│   │   ├── api.py      # REST API endpoints
│   │   └── static/     # HTML, CSS, JavaScript
│   ├── db/             # Database layer
│   ├── rpc/            # Blockchain RPC integration
│   ├── stratum/        # Stratum protocol handler
│   └── config.py       # Configuration management
├── config/             # Configuration files
├── docker-compose.yml  # Docker setup
├── requirements.txt    # Python dependencies
└── README.md          # Project documentation
```

## Key Areas for Contribution

- **Bug fixes** - Help us squash bugs!
- **UI/UX improvements** - Enhance the dashboard
- **Performance** - Optimize database queries and API calls
- **Documentation** - Improve README, guides, and comments
- **Testing** - Add validation scenarios
- **Features** - New capabilities like additional metrics or notifications

## Performance and Security Considerations

### Performance

- Minimize database queries - use JOINs when appropriate
- Cache frequently accessed data
- Use efficient algorithms and data structures
- Profile code to identify bottlenecks

### Security

- Never commit secrets or credentials
- Validate all user inputs
- Use parameterized queries to prevent SQL injection
- Keep dependencies updated
- Report security issues privately (see SECURITY.md)

## Questions?

- Check existing issues and discussions
- Review the documentation in README.md and DASHBOARD.md
- Open a discussion for general questions

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

---

Thank you for contributing to make KCN Proxy better! 🚀
