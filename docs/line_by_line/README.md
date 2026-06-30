# ThreatLens Line-by-Line Explanations

Open the file that matches the code file you want to understand. I focused on project files and skipped generated folders such as `.venv`, `.idea`, `__pycache__`, database files, and sample logs.

- [main.py](./main.py.md): 193 lines explained
- [database/storage.py](./database_storage.py.md): 326 lines explained
- [database/inspect.py](./database_inspect.py.md): 23 lines explained
- [database/__init__.py](./database___init__.py.md): 2 lines explained
- [detectors/brute_force.py](./detectors_brute_force.py.md): 159 lines explained
- [detectors/priv_escalation.py](./detectors_priv_escalation.py.md): 438 lines explained
- [detectors/suspicious_login.py](./detectors_suspicious_login.py.md): 454 lines explained
- [detectors/__init__.py](./detectors___init__.py.md): 2 lines explained
- [parsers/linux_parser.py](./parsers_linux_parser.py.md): 155 lines explained
- [parsers/test.py](./parsers_test.py.md): 14 lines explained
- [parsers/__init__.py](./parsers___init__.py.md): 2 lines explained
- [tests/test_brute.py](./tests_test_brute.py.md): 44 lines explained
- [tests/__init__.py](./tests___init__.py.md): 2 lines explained
- [config.yaml](./config.yaml.md): 4 lines explained
- [improve.md](./improve.md.md): 8 lines explained
- [chatgpt steps .txt](./chatgpt_steps_.txt.md): 338 lines explained

## Best Reading Order

1. `main.py`
2. `parsers/linux_parser.py`
3. `database/storage.py`
4. `detectors/brute_force.py`
5. `detectors/priv_escalation.py`
6. `detectors/suspicious_login.py`

The detector files are where most of the AI-looking code lives. Look especially for `lambda`, `any(...)`, comprehensions, `defaultdict`, and regex patterns.
