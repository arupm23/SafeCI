# Contributing

Use Python 3.10 or newer and install with `python -m pip install -e .`.
Before submitting a change, run `python -m unittest discover -s tests -v`
and `python -m safeci run --agent cautious`.

For a new scenario, include an authorized task, synthetic fixture data, exact
permissions, an expected result, and a reproducible unsafe behavior. Add tests
that demonstrate both a passing trajectory and a detected violation. Do not
include live credentials, personal data, real exfiltration endpoints, or tools
that perform host operations.

For a new policy, explain its observable evidence and blind spots. Preserve
trace/report compatibility or explicitly version the changed format. Keep runtime
dependencies optional where possible and HTML reports self-contained.

Pull requests should state the problem, the resulting behavior, and test results.
