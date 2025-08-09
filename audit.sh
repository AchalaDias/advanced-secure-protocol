## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

# 1. Dependency vulnerabilities
pip-audit
safety scan --full-report

# 2. Code issues
bandit -r .

# 3. Secrets
gitleaks detect --source .

