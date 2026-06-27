Add a parser for Windows EVTX logs.

Add an "event_type" field such as:

"event_type": "failed_login"

Consider using Pydantic models or dataclasses instead of raw dictionaries once the project grows.
Add unit tests for parsers.