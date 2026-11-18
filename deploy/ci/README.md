# Le Fureteur — CI/CD integration

1. In the web interface open **API & CI/CD** and create a token with the `scan` scope (plus `read`), limited to the project. The value is shown only once.
2. Add pipeline secrets: `LF_URL` (e.g. `https://fureteur.example.com`), `LF_PROJECT` (project number) and `LF_TOKEN`.
3. Copy one of the templates: `github-actions.yml`, `gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`.

The client (`lf_ci.py`) is downloaded from your server and only needs Python 3. It packages the repository (excluding `.git`,
`node_modules` and virtual environments), uploads it and waits for the result. Exit code: **0** passed · **1** failed the policy gate · **2** error.

| Option | Description |
|---|---|
| `--file sbom.cdx.json` | Upload a single file instead of a folder (CycloneDX / SPDX SBOM, lock file, JAR, image .tar, APK) |
| `--fail-on HIGH` | Severity threshold: CRITICAL / HIGH / MEDIUM / LOW / NONE (default: project setting) |
| `--kev true\|false`, `--license true\|false` | Fail on actively exploited (KEV) findings / denied licenses |
| `--new-only` | Only findings new in this scan affect the gate (useful for projects with existing debt) |
| `--sarif file` | Write SARIF 2.1.0 (GitHub / GitLab / Azure code scanning) |
| `--no-fail` | Report only; always exit 0 |
| `--cacert ca.pem` | Internal certificate authority |

Policy defaults are managed per project in the web interface (project → Project settings → CI policy).
If the server is on an internal network, use a self-hosted runner (GitHub / GitLab runner, Jenkins agent).
