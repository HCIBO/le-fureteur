# End-to-end integration tests (SSO, SMTP, Slack, Teams, webhook, Jira)

These tests run against **local** stand-ins for the real services; no request leaves the machine.

1. `docker compose -f tests/e2e/docker-compose.yml up -d` (Keycloak + Mailpit)
2. Create the Keycloak realm, client and users:
   ```bash
   K="docker compose -f tests/e2e/docker-compose.yml exec keycloak /opt/keycloak/bin/kcadm.sh"
   $K config credentials --server http://localhost:8080 --realm master --user admin --password admin-test-only
   $K create realms -s realm=lefureteur -s enabled=true
   $K create clients -r lefureteur -s clientId=le-fureteur -s publicClient=false -s secret=kc-test-secret-only \
      -s 'redirectUris=["http://localhost:8812/api/auth/oidc/callback"]'
   $K create users -r lefureteur -s username=carol -s email=carol@acme.test -s emailVerified=true -s enabled=true
   $K set-password -r lefureteur --username carol --new-password 'Kc-Deneme-2026'
   $K create users -r lefureteur -s username=ghost -s email=ghost@acme.test -s emailVerified=true -s enabled=true
   $K set-password -r lefureteur --username ghost --new-password 'Kc-Deneme-2026'
   ```
3. Start the mock Slack / Teams / webhook / Jira server: `python3 tests/e2e/mock_integrations.py <work dir>/b8/mock.log`
4. Run Le Fureteur on `http://localhost:8812` (with test data containing the admin@test.local and carol@acme.test accounts and target 10),
   then: `python tests/e2e/integrations_e2e.py <work dir>`

Covered: SMTP test message (Mailpit), OIDC discovery + JWKS, Jira connection and issue creation, test delivery for all four channel
types, Slack / Teams formatting, webhook HMAC signature, notifications to every channel when a scan finishes, browser login through
Keycloak, rejection of corporate users without a Le Fureteur account, and the login being recorded as "sso".

## Browser helper (site behind a WAF)

`fake_waf_site.py` serves a Cloudflare-like challenge page on 127.0.0.1:8777 (403 + "Just a moment..." without the cookie).
`capture_e2e.py`: the web scan is blocked by the WAF → a ticket is issued → `scakit/capture_client.py` (with LF_CAPTURE_HEADLESS=1,
tests only) waits for the challenge to pass, crawls the pages (never visits /logout), cleans and uploads the recording → the scan starts.
