# 1. Dependency vulnerabilities
pip-audit
safety scan --full-report

# 2. Code issues
bandit -r .

# 3. Secrets
gitleaks detect --source .

