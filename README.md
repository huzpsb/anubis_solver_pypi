# anubis-solver

Solve Anubis Web AI Firewall challenges.  
[Anubis](https://github.com/TecharoHQ/anubis)

## Install
```bash
pip install anubis-solver
```

## Use

```python
import requests
from anubis_solver import solve

cookie = solve("https://fabulous.systems/")
print(cookie)

content = requests.get("https://fabulous.systems/", headers={"Cookie": cookie}, verify=False).text
print(content)
```

