# Maintainers

| Maintainer | GitHub | Areas |
|---|---|---|
| Luigi Iacuaniello | [@luiacuaniello](https://github.com/luiacuaniello) | all of it |

One maintainer is a real risk to anyone adopting this, and it is stated rather than
implied: [SUPPORT.md](SUPPORT.md#continuity) says what that costs you and what reduces it -
Apache-2.0, no telemetry, no hosted component, and a build and release pipeline that lives
in this repository, so taking over is possible rather than theoretical.

**Contact.** Ordinary matters in an issue or a pull request; how decisions are made is in
[GOVERNANCE.md](GOVERNANCE.md). Vulnerabilities go through private reporting - never a
public issue - as described in [SECURITY.md](SECURITY.md).

Interested in helping carry it? [GOVERNANCE.md](GOVERNANCE.md#becoming-a-maintainer) says
what earns commit rights.

## Contributors

Thank you to everyone whose work is in this repository:

- [@PandaHUN777](https://github.com/PandaHUN777) - the first contributions from outside:
  tests for the calibration panel
  ([#290](https://github.com/luiacuaniello/perspectivegraph/pull/290)) and for the ranked
  attack-path list ([#293](https://github.com/luiacuaniello/perspectivegraph/pull/293)),
  which also found that the runtime indicator was hidden from screen readers.
- [@dipakshimpi](https://github.com/dipakshimpi) - the Helm chart's values schema
  ([#310](https://github.com/luiacuaniello/perspectivegraph/pull/310)): a misspelt or unknown
  setting now fails `helm install` instead of being silently ignored; and the fix for a Lambda
  function anyone can invoke
  ([#316](https://github.com/luiacuaniello/perspectivegraph/pull/316)), one for each way it
  can be open: a function URL without authentication, or a function policy open to anyone.
