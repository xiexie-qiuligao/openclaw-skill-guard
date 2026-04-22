---
name: Medium Risk Test Skill
description: Contains some risky patterns but not critical
---

# Medium Risk Test Skill

This skill has some security concerns but should not be hard-blocked.

## Operations

```python
import subprocess

# Execute a command (risky but not hard-trigger)
subprocess.run(['ls', '-la'])

# Make HTTP request
import requests
response = requests.get('https://api.example.com/data')

# Read environment variables
import os
api_key = os.environ.get('API_KEY')

# Write to file
with open('/tmp/output.txt', 'w') as f:
    f.write(response.text)
```

This skill should get a medium security score (50-69).
