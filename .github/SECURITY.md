# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the KCN Proxy project, please **do not** open a public issue. Instead, please report it responsibly by emailing the maintainers directly.

### How to Report

1. **Do not create a public GitHub issue** - This could expose the vulnerability before a fix is available
2. **Contact the maintainers privately** with:
   - Description of the vulnerability
   - Steps to reproduce (if applicable)
   - Potential impact
   - Suggested fix (if you have one)

Contact: [@cdonnachie](https://github.com/cdonnachie) via GitHub or use GitHub's private security advisory feature

### What to Expect

- We will acknowledge receipt of your report within 48 hours
- We will work on a fix as soon as possible
- We will keep you updated on the progress
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- Once fixed, we will release a patched version

## Security Best Practices

### For Users

1. **Keep the proxy updated** - Always run the latest version
2. **Use environment variables** - Store sensitive data in `.env` files, not in code
3. **Secure RPC connections** - Use HTTPS/TLS for RPC endpoints
4. **Monitor logs** - Watch for unusual activity
5. **Network security** - Run the proxy behind a firewall
6. **Authentication** - If exposing the dashboard, add authentication

### For Contributors

1. **Never commit secrets** - Credentials, API keys, or tokens should never be in the repository
2. **Input validation** - Always validate and sanitize user input
3. **SQL injection prevention** - Use parameterized queries
4. **Error handling** - Don't expose sensitive information in error messages
5. **Dependencies** - Keep dependencies up to date
6. **Code review** - Security-sensitive changes should be reviewed carefully

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest  | ✅ Yes    |
| n-1     | ✅ Yes    |
| < n-1   | ❌ No     |

We recommend always running the latest version for security updates.

## Security Updates

Security patches will be released as soon as they are ready and tested. We follow semantic versioning and will typically release security patches as minor or patch version updates.

## Known Security Considerations

- The dashboard should not be exposed to the public internet without authentication
- The proxy should only connect to trusted RPC endpoints
- Configuration files should be protected and not world-readable
- Database files should be secured with appropriate file permissions

## Responsible Disclosure

We appreciate the security research community and believe that responsible disclosure of vulnerabilities protects all users. We will make our best effort to:

- Acknowledge the receipt of your report
- Provide a reasonable timeline for patching
- Credit researchers (with permission)
- Keep the vulnerability details confidential until a patch is available

Thank you for helping keep KCN Proxy secure!
