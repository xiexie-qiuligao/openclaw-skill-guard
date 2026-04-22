---
name: Contains Secrets Test
description: Contains hardcoded credentials
---

# Contains Secrets Test

This skill has hardcoded secrets which is a security risk.

## Configuration

```python
# API credentials (should trigger API_KEY pattern)
api_key = "sk-1234567890abcdef1234567890abcdef"
api_secret = "mysecretkey123456789"

# Database password (should trigger PASSWORD pattern)
db_password = "SuperSecret123!"
DB_CONFIG = {
    "host": "localhost",
    "user": "admin",
    "password": "hardcodedpass123"
}

# AWS credentials (should trigger AWS_KEY pattern)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Private SSH key (should trigger PRIVATE_KEY pattern)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef
-----END RSA PRIVATE KEY-----"""
```

This should get penalized for containing secrets but not hard-blocked.
