# Execution record

Local execution of `python -m pytest -v --tb=short tests/test_engine.py tests/test_correlator.py`. The input and output shown come from the repository example or test fixtures.

- `python -m pytest -v --tb=short tests/test_engine.py tests/test_correlator.py` — exit 0.

The image renders the captured terminal output. [Full transcript](screenshots/execution.txt).

Latest local test output:

```text
============================= test session starts ==============================
platform linux -- Python 3.12.14, pytest-8.4.2, pluggy-1.6.0
rootdir: threat-correlation-engine
configfile: pyproject.toml
testpaths: tests
plugins: cov-7.1.0, platformdirs-4.12.2, anyio-4.15.1, asyncio-1.4.0, respx-0.23.1
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 20 items

tests/test_correlator.py ...........                                     [ 55%]
tests/test_engine.py .........                                           [100%]

============================== 20 passed in 0.10s ==============================
```

This record covers the local commands and fixtures shown. External services and deployment remain unverified unless explicitly listed.
