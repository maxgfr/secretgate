# Changelog

All notable changes to this project are documented here, generated automatically from the Conventional Commits by semantic-release.

# 1.0.0 (2026-07-13)


### Bug Fixes

* **cli:** resolve real paths in entrypoint guard so the pinned bundle runs behind symlinks ([9dde7de](https://github.com/maxgfr/secretgate/commit/9dde7de6fd3f135781ba7b1069b5560953ef7085))
* skills-only distribution + 3 correctness bugs found by real-world Claude testing ([d5fc796](https://github.com/maxgfr/secretgate/commit/d5fc796365bf068382f49aff2a961262a7c3356a))


### Features

* **claude-code:** full adapter — prompt block with redacted copy, sensitive-path deny, redact-and-restore hooks, idempotent installer ([5a37b72](https://github.com/maxgfr/secretgate/commit/5a37b72729b15a559b24939411cab03162f0d104))
* **cli:** vault with HMAC placeholders + redact/restore + scan/pipe/allow/vault commands ([ee7d251](https://github.com/maxgfr/secretgate/commit/ee7d2519f56b49fbd900070942017029b55bf9be))
* **codex:** adapter (prompt block + tool-input protection, post no-op documented) + hooks.json/config.toml installer with managed TOML block ([30d43c8](https://github.com/maxgfr/secretgate/commit/30d43c8e68b4a9be6172c5acd83444700b49781d))
* **engine:** gitleaks-derived detection engine — 222 converted rules, entropy/keyword/stopword gates, Luhn+IIN card rule, hybrid gitleaks pass ([1ea6363](https://github.com/maxgfr/secretgate/commit/1ea6363b38eb37a6df95e1f3cc9551de45ebc7e1))
* **opencode:** plugin with in-place prompt redaction, tool deny/restore, output redaction + installer (plugin-file and via-config modes) ([9d8e4c8](https://github.com/maxgfr/secretgate/commit/9d8e4c848b7373ce71787b08917c72798f9c9a6b))
* scaffold secretgate CLI (family conventions, two-bundle tsup, vendored gitleaks rules) ([6537602](https://github.com/maxgfr/secretgate/commit/65376021ac2f37e54020e9704084d7f2bde9f9cf))
* status doctor, path-only/scoped rule semantics, self-scan dogfood clean, SKILL.md + README threat model, rules:sync ([6bc1a6e](https://github.com/maxgfr/secretgate/commit/6bc1a6e2bd2464aa4cf302760cb2abab6202f03b))
