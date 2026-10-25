# Built Azure Login: NO_PROXY regression comparison

This manual workflow compares the actual built Azure Login action before and
after PR #630, using GitHub OIDC and a real Azure CLI login. It does not create
Azure resources. The existing `azure-login-live-tests.yml` is unchanged.

## Prerequisites and execution

- Use the fork's `Automation test` GitHub Environment and its existing
  `SP1_CLIENT_ID`, `SP1_TENANT_ID`, and `SP1_SUBSCRIPTION_ID` secrets.
- SP1 needs federated trust for this fork and Environment, and access to the
  selected subscription. No client secret, SP2, or provisioning credential is used.
- The workflow must exist on the default branch for manual dispatch. Run
  **NO_PROXY: built Azure Login comparison** on `verify-pr-630`, which is allowed
  by this fork's existing Environment deployment rules. The separate
  `verify-no-proxy-pr-630` branch contains the same harness but is not allowed by
  those rules; Environment protection was not relaxed for this experiment.

## Pinned sources and expectations

The helper checks both the source SHA and the dependency versions resolved from
`@actions/core` itself after `npm ci`. It builds the main and cleanup entrypoints
with the source's own build script and records SHA256 hashes of both bundles.
The action runs through `uses: ./action-under-test` without source modifications.

| Variant | Source SHA | core | http-client |
| --- | --- | --- | --- |
| before | `fcd03407c33dcc2d7daa4be58fbc6cc97f863e47` | 1.11.1 | 2.0.1 |
| pr | `f6a8c089320d041a212e55c4dfb04f742398fbe1` | 2.0.3 | 3.0.2 |

| Scenario | before | pr |
| --- | --- | --- |
| baseline: no proxy | success | success |
| exact: NO_PROXY is the OIDC hostname | success | success |
| parent: NO_PROXY is the hostname's DNS parent | OIDC proxy rejection | success |
| unrelated: NO_PROXY does not match | OIDC proxy rejection | OIDC proxy rejection |

Each matrix cell runs on a separate Ubuntu runner with an isolated Azure CLI
configuration directory. Lowercase proxy variables are scoped to the login step;
inherited uppercase proxy variables are cleared to prevent conflicting settings. Build and checkout
steps do not inherit the experimental proxy settings. PowerShell login is off;
the existing live suite covers ordinary PowerShell behavior separately.

## Proxy and result evidence

`probe.py` starts an HTTP CONNECT proxy bound only to `127.0.0.1:3128` using the
Python standard library. It refuses the actual hostname extracted from
`ACTIONS_ID_TOKEN_REQUEST_URL` and tunnels other HTTPS authorities. It does not
decrypt TLS. The OIDC issuer URL is not used as a substitute for the request host.

Before measuring the action, controls prove the OIDC CONNECT is refused and an
Azure discovery request works through the proxy. Those control connections are
excluded from result counts. A successful proxied scenario requires no OIDC
proxy rejection, at least one CONNECT to `login.microsoftonline.com`, and an
active CLI account matching SP1's client, tenant, and subscription. An expected
failure requires both an action failure and an OIDC CONNECT rejection. A generic
authentication/network failure without that evidence fails verification.

Each job writes a sanitized table to the run Summary, including source SHA,
dependency versions, bundle digest, hostname, and connection counts. No request
headers, bearer tokens, JWTs, or full OIDC request URLs are written by the helper.
Use normal action logging; do not enable request/runner debug logging for this
experiment. Expected action failures are handled by the verification step, so
all eight jobs should be green when the regression is reproduced.

The proxy is stopped in an `always()` step. Azure Login's own post action clears
the job's CLI account cache; no resource-group teardown is needed.

## Local checks

```bash
python3 -m unittest discover -s scripts/no-proxy-login -p 'test_*.py' -v
```

Tests cover the expected matrix, rejection of unrelated failures, the evidence
boundary, actual CONNECT denial, opaque byte forwarding, and omission of headers
and payloads from proxy logs. Real GitHub OIDC and Azure authentication must be
verified on GitHub Actions.
