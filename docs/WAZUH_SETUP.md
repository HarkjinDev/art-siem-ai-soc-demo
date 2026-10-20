# Wazuh 4.14.5 — official stack setup (optional)

Do **not** reuse the uploaded ZIP as a distributable Wazuh image/config: it contains passwords and private keys.

1. From project root, run `powershell -File scripts/prepare-wazuh.ps1` (or `bash scripts/prepare-wazuh.sh`).
2. Inspect `wazuh-upstream/single-node/README.md` and the official [Wazuh Docker guide](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).
3. Configure **new strong passwords**, generate new certificates using upstream `generate-indexer-certs.yml` and official procedure, then start Wazuh from its **own** official Compose directory.
4. For SOC demo integration provide `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, `WAZUH_CA_FILE` and place the **public CA** at `certs/root-ca.pem`. Using `host.docker.internal` can fail if the server certificate SAN does not include it: use a certificate-matching DNS hostname.
5. From SOC dashboard use “실제 Wazuh 최근 10건 가져오기”. Imported events do not write to Wazuh.

**Current limitation**: Wazuh requires its own initialized official Compose stack. v0.2 does not yet supply a unified `docker compose up` to provision/indexer passwords/certificates safely. The two stacks can run side by side.
