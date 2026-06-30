# Line-by-Line Explanation: config.yaml

This file explains every line in `config.yaml`. The original line is shown first, followed by a plain-English explanation.

| Line | Code | Explanation |
|---:|---|---|
| 1 | `abuseipdb:` | Starts a configuration section. The indented lines below belong to this section. |
| 2 | `  api_key: "e082ec44cead035a481b5b75a8a6a2a8e3c81cd5319a8c37bb1405ec63cd1b29f5366fbfc8dc2dc5"` | Defines a configuration value. The text before the colon is the setting name, and the text after the colon is its value. |
| 3 | `  cache_hours: 24      # don't re-query same IP within 24 hours` | Defines a configuration value. The text before the colon is the setting name, and the text after the colon is its value. |
| 4 | `  min_score_alert: 25  # flag IPs scoring above this` | Defines a configuration value. The text before the colon is the setting name, and the text after the colon is its value. |
