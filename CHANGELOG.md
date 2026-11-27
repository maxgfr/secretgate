# Changelog

All notable changes to this project are documented here, generated automatically from the Conventional Commits by semantic-release.

# [1.10.0](https://github.com/maxgfr/secretgate/compare/v1.9.0...v1.10.0) (2026-11-27)


### Features

* **scanner:** find secrets behind one layer of base64, hex or percent-encoding ([880e2fa](https://github.com/maxgfr/secretgate/commit/880e2fa2926554618e3817730c32937d16b74c85))

# [1.9.0](https://github.com/maxgfr/secretgate/compare/v1.8.1...v1.9.0) (2026-11-16)


### Bug Fixes

* **verifier:** a hard time bound in a child process, and the user's disabled rules ([312f5b3](https://github.com/maxgfr/secretgate/commit/312f5b3a1befc75e0d80ab379a58419455f314a2))
* **verifier:** delete batch records older than 24 hours ([f3b5f9a](https://github.com/maxgfr/secretgate/commit/f3b5f9ae5734a1032bb1d082ccd2511e7d790592))
* **verifier:** redact only the spans it accepts; drop value propagation ([bc7ae98](https://github.com/maxgfr/secretgate/commit/bc7ae98f6b0f42cc95b7f29cd4b415278322ef20))
* **verifier:** spread a value only as a whole, unusual token; never touch keys; one deadline per event; no path from a session id ([4dc10a5](https://github.com/maxgfr/secretgate/commit/4dc10a5ff236bd5881074832ab61df33070720eb))


### Features

* an experimental, opt-in ML verifier after the rules (s6-secrets-verify-pico) ([93522bd](https://github.com/maxgfr/secretgate/commit/93522bdff35329c34851f7604d35a2af3c956b39))

## [1.8.1](https://github.com/maxgfr/secretgate/compare/v1.8.0...v1.8.1) (2026-11-14)


### Bug Fixes

* **claude-code:** reading a PDF or an image no longer stops the session ([9ecc588](https://github.com/maxgfr/secretgate/commit/9ecc588cfc06f94d622505cc6dd717f7389d3620))
* **claude-code:** stop the turn when a failed tool call printed a secret ([09aa615](https://github.com/maxgfr/secretgate/commit/09aa615dfe439f1e1b5daa517a215e44863a5497))
* **engine:** a forged placeholder no longer hides the value written around it ([8768a57](https://github.com/maxgfr/secretgate/commit/8768a5767450200236bf2d4cb922428d4990f658))
* **engine:** drop a value only when the text makes it certain, not on its look ([e5834b9](https://github.com/maxgfr/secretgate/commit/e5834b988dcb69825f0f5bd512cac6d57b570cf8))
* **engine:** nothing around a value reads placeholder text, and unsettled redaction fails closed ([e482c17](https://github.com/maxgfr/secretgate/commit/e482c173c041a72e8c13413949f08f1db60fe17a))
* **engine:** only a name that says "public" exempts a value, and no credential word may stand beside it ([4f4ddee](https://github.com/maxgfr/secretgate/commit/4f4ddeede3545b17a1efdc452b1c233c0e4a59d3))
* **engine:** only a separator or two may stand around a placeholder ([0ebd2bf](https://github.com/maxgfr/secretgate/commit/0ebd2bf7bed2b31025074ea80be933cd13e72b12))
* **engine:** redact the whole flagged value when a vendor token is only part of it ([f1e41cc](https://github.com/maxgfr/secretgate/commit/f1e41cc242c95a789ac270a78de9160f6814c2c3))
* **engine:** redacted text is no longer flagged a second time ([7dddcc2](https://github.com/maxgfr/secretgate/commit/7dddcc28cc120e99af4f238aed10aa538d3a0533))
* **engine:** stop flagging values that say themselves they are not secrets ([bc9633e](https://github.com/maxgfr/secretgate/commit/bc9633e14c01305552a6590a40cc3c47c4d1e3c7))
* **engine:** the value-after-a-credential rule is the AWS key pair, nothing wider ([7c0bfa6](https://github.com/maxgfr/secretgate/commit/7c0bfa60d954362f14138d4f7c93fc6547175c88))
* **hooks:** a binary field is skipped for what it holds, not for what it is called ([0f19bfe](https://github.com/maxgfr/secretgate/commit/0f19bfe08d67561fa5ab4cef1b50f5379c7cfae6))
* **hooks:** find -exec mv/ln is refused for where the file lands, not for what the tree holds ([7d0a99d](https://github.com/maxgfr/secretgate/commit/7d0a99de2872c6ff6cd6e88b3c2da6e5ab8ad453))
* **hooks:** moving a sensitive file into a fixture directory, in its other spellings ([95451f9](https://github.com/maxgfr/secretgate/commit/95451f9ad396138becfe30516f0982f959a1c609))
* **hooks:** PostToolBatch no longer stops on output PostToolUse redacted ([2f4eb2d](https://github.com/maxgfr/secretgate/commit/2f4eb2d52b3d55ac1e13efc8d087054a97601fa0))
* **hooks:** refuse moving a sensitive file into a fixture directory ([6179c4d](https://github.com/maxgfr/secretgate/commit/6179c4dbe5e8ca62124562e44be2c8b096c01d37))
* **hooks:** text in a base64-shaped field is scanned again ([743e20e](https://github.com/maxgfr/secretgate/commit/743e20ea9a7e71e76491f0b133326669b79ef204))
* **install:** a settings link is followed only to a file that can be a settings file ([aba4dc3](https://github.com/maxgfr/secretgate/commit/aba4dc33aa9d2da7a1b6bfc5f8c2b0878959fd12))
* **install:** Claude Code's version comes from a claude the project cannot plant, in the shape it prints ([bf523d3](https://github.com/maxgfr/secretgate/commit/bf523d3bc0f7b934e4796e50d67acc72d7cfbd9d))
* **install:** keep the permission bits and the symlink of the settings it edits ([ca9f065](https://github.com/maxgfr/secretgate/commit/ca9f065e534a8299f2cd888288d522032eb80b4b))
* **install:** refuse a settings symlink that leads out of its own tree ([0cee9ee](https://github.com/maxgfr/secretgate/commit/0cee9eeafeda5fa6a8d031b5744ce6a86799f348))
* **install:** write the PostToolBatch hook only for a Claude Code that tolerates it ([a11138c](https://github.com/maxgfr/secretgate/commit/a11138cabd79f654f4a0a7fc30053ac68161548c))

# [1.8.0](https://github.com/maxgfr/secretgate/compare/v1.7.1...v1.8.0) (2026-10-20)


### Features

* support OpenCode 2 only ([#13](https://github.com/maxgfr/secretgate/issues/13)) ([22c2715](https://github.com/maxgfr/secretgate/commit/22c27157a4b94f26cedc43cf0ec11feb679ad448))

## [1.7.1](https://github.com/maxgfr/secretgate/compare/v1.7.0...v1.7.1) (2026-10-13)


### Bug Fixes

* **install:** uninstall removes the deny rules a <= 1.4 install left unrecorded ([#12](https://github.com/maxgfr/secretgate/issues/12)) ([ea41b72](https://github.com/maxgfr/secretgate/commit/ea41b7220a9621ccf8dda50d49bddd38c139b615))

# [1.7.0](https://github.com/maxgfr/secretgate/compare/v1.6.4...v1.7.0) (2026-10-12)


### Features

* **engine:** detect Groq, Replicate and xAI keys and Discord webhook URLs ([e497a3c](https://github.com/maxgfr/secretgate/commit/e497a3ce87667fa075cfdb403d83f5fc9bcd5876))

## [1.6.4](https://github.com/maxgfr/secretgate/compare/v1.6.3...v1.6.4) (2026-10-12)


### Bug Fixes

* close the gaps a review of the audit fixes found ([073ac99](https://github.com/maxgfr/secretgate/commit/073ac999513a7f67d555400bd0b26ef7b41159d2))
* **engine:** record a text's secrets in one vault cycle and restore hex-adjacent placeholders ([4fc01b9](https://github.com/maxgfr/secretgate/commit/4fc01b9f67701cd27dc7b23381ffd12e49768dfe))
* **hooks:** only a first-line /secretgate directive pauses a session; harden config, allow and status ([87b6473](https://github.com/maxgfr/secretgate/commit/87b6473faa022304095c819ae1e1c36925e88494))
* **install:** valid Codex TOML, JSONC-safe OpenCode uninstall, absolute node in hooks ([098ca40](https://github.com/maxgfr/secretgate/commit/098ca40a5dd75ed5fad3da8bdb2702be949db21c))
* **shell:** close the analyser bypasses found in the audit ([328f595](https://github.com/maxgfr/secretgate/commit/328f5953791219e5360441095da2c96b68a0a7bb))

## [1.6.3](https://github.com/maxgfr/secretgate/compare/v1.6.2...v1.6.3) (2026-10-11)


### Bug Fixes

* **scope:** restate search counts after filtering, honour OPENCODE_CONFIG_DIR ([49e3c4f](https://github.com/maxgfr/secretgate/commit/49e3c4f4c2552831855b7c6b398bb4294813b631))

## [1.6.2](https://github.com/maxgfr/secretgate/compare/v1.6.1...v1.6.2) (2026-10-11)


### Bug Fixes

* **opencode:** support the OpenCode 2 plugin API ([#9](https://github.com/maxgfr/secretgate/issues/9)) ([9b71a40](https://github.com/maxgfr/secretgate/commit/9b71a40d50bda5345c1b7ec614f06698e1697bfe))

## [1.6.1](https://github.com/maxgfr/secretgate/compare/v1.6.0...v1.6.1) (2026-10-01)


### Bug Fixes

* catch sed -I and gawk inplace edits of policy files, and check pins against the right program ([#8](https://github.com/maxgfr/secretgate/issues/8)) ([d312b3c](https://github.com/maxgfr/secretgate/commit/d312b3c73b2e774c770051f4b11503477f8a5343))

# [1.6.0](https://github.com/maxgfr/secretgate/compare/v1.5.2...v1.6.0) (2026-09-30)


### Features

* standalone binary for Homebrew, no Node required ([#7](https://github.com/maxgfr/secretgate/issues/7)) ([76d7479](https://github.com/maxgfr/secretgate/commit/76d74796c122892b6c5035d9e24d223b7397b179))

## [1.5.2](https://github.com/maxgfr/secretgate/compare/v1.5.1...v1.5.2) (2026-09-30)


### Bug Fixes

* **status:** say that [@file](https://github.com/file) mentions are checked by the prompt hook ([52748d8](https://github.com/maxgfr/secretgate/commit/52748d8bf8eb0a97c64318b5e0a8b10812339256))

## [1.5.1](https://github.com/maxgfr/secretgate/compare/v1.5.0...v1.5.1) (2026-09-30)


### Bug Fixes

* act on the GLM 5.3 review — in-place edits, @-mentions, vault lock, scan reporting ([8daff63](https://github.com/maxgfr/secretgate/commit/8daff636666b3d3d0abda9873b828454a6102d8d))
* **install:** remove retired deny rules from pre-ownership installs, and never take another tool's hook for secretgate's ([11bd9af](https://github.com/maxgfr/secretgate/commit/11bd9af91dd8ff61a079a525e7f1dd348838558e))

# [1.5.0](https://github.com/maxgfr/secretgate/compare/v1.4.1...v1.5.0) (2026-09-30)


### Bug Fixes

* act on the branch review, and stop blocking security-fix work on test fixtures ([6d39d61](https://github.com/maxgfr/secretgate/commit/6d39d61f17f38c25a0d42f542928f90ce6c69fa1))


### Features

* **scope:** fence agents into part of a repo, and harden every hook path ([cea9af3](https://github.com/maxgfr/secretgate/commit/cea9af3717217872e43363fbe811b8301b72adfe))

## [1.4.1](https://github.com/maxgfr/secretgate/compare/v1.4.0...v1.4.1) (2026-09-30)


### Bug Fixes

* **disable:** target the host's session id, not the newest indexed run ([4ec5c82](https://github.com/maxgfr/secretgate/commit/4ec5c82855a745ea69d53dade3b871fe6ff113f1))

# [1.4.0](https://github.com/maxgfr/secretgate/compare/v1.3.3...v1.4.0) (2026-09-11)


### Features

* **skill:** let the agent invoke secretgate, with an explicit-only opt-out ([36ebfb0](https://github.com/maxgfr/secretgate/commit/36ebfb012fc21d79bd5bf59edd22ee2f93bcdf07))

## [1.3.3](https://github.com/maxgfr/secretgate/compare/v1.3.2...v1.3.3) (2026-09-09)


### Bug Fixes

* **skills:** preserve manual invocation across agent hosts ([1d90e8a](https://github.com/maxgfr/secretgate/commit/1d90e8a59a226bb495674469f2ed340a9d61a2fe))

## [1.3.2](https://github.com/maxgfr/secretgate/compare/v1.3.1...v1.3.2) (2026-09-08)


### Bug Fixes

* harden and verify Claude Code, Codex and OpenCode integrations ([eb2367b](https://github.com/maxgfr/secretgate/commit/eb2367b2c401ca236052fc45a8642c389b390d0c))

## [1.3.1](https://github.com/maxgfr/secretgate/compare/v1.3.0...v1.3.1) (2026-08-25)


### Bug Fixes

* **codex:** protect tool output and trust hooks ([3a57198](https://github.com/maxgfr/secretgate/commit/3a57198936b39a69ad6c301cb8604223cb85ff1a))

# [1.3.0](https://github.com/maxgfr/secretgate/compare/v1.2.0...v1.3.0) (2026-08-10)


### Features

* **disable:** session-lifetime scope — off for this run, auto re-enabled next session ([#4](https://github.com/maxgfr/secretgate/issues/4)) ([581aceb](https://github.com/maxgfr/secretgate/commit/581aceb658ba0f55b20ea0e7446bb0da253b18ab))

# [1.2.0](https://github.com/maxgfr/secretgate/compare/v1.1.9...v1.2.0) (2026-08-10)


### Features

* **cli:** disable the firewall for one run, three scopes, always time-bounded ([7e722d6](https://github.com/maxgfr/secretgate/commit/7e722d696107fad7e4c3ab882148f7dca997db2f))

## [1.1.9](https://github.com/maxgfr/secretgate/compare/v1.1.8...v1.1.9) (2026-07-25)


### Bug Fixes

* **engine:** cut the false positives measured on a 42k-file corpus ([6718aaa](https://github.com/maxgfr/secretgate/commit/6718aaab4da6b52d7cdcc3ea4303b3a8afc6d26a))

## [1.1.8](https://github.com/maxgfr/secretgate/compare/v1.1.7...v1.1.8) (2026-07-25)


### Bug Fixes

* **engine:** write the path example as a real path so the self-scan passes ([ac571fe](https://github.com/maxgfr/secretgate/commit/ac571fec5acc746870034cd91683e8f52f7cf8dc))

## [1.1.7](https://github.com/maxgfr/secretgate/compare/v1.1.6...v1.1.7) (2026-07-25)


### Bug Fixes

* **engine:** stop redacting filesystem paths and placeholder values ([b677343](https://github.com/maxgfr/secretgate/commit/b6773437a0b3f59e464172c10f2aad1d9f7c85c7)), closes [hi#entropy](https://github.com/hi/issues/entropy)

## [1.1.6](https://github.com/maxgfr/secretgate/compare/v1.1.5...v1.1.6) (2026-07-17)


### Bug Fixes

* **cli:** report a single claude-code scope when cwd is the home directory ([4c16ac8](https://github.com/maxgfr/secretgate/commit/4c16ac8785b3b7575aee7682a3941fc50ab55e55))

## [1.1.5](https://github.com/maxgfr/secretgate/compare/v1.1.4...v1.1.5) (2026-07-17)


### Bug Fixes

* **claude-code:** emit "{}" instead of empty stdout on clean pre-tool-use (claude-code[#77782](https://github.com/maxgfr/secretgate/issues/77782)) ([1df2053](https://github.com/maxgfr/secretgate/commit/1df2053a0a56bb51f4b0b81f0a4470d14b025bd0))

## [1.1.4](https://github.com/maxgfr/secretgate/compare/v1.1.3...v1.1.4) (2026-07-17)


### Bug Fixes

* **deps:** force esbuild >=0.28.1 (GHSA dev-server arbitrary file read) ([#3](https://github.com/maxgfr/secretgate/issues/3)) ([e79518c](https://github.com/maxgfr/secretgate/commit/e79518c05c08018964db3efcde1a36ff9d49cc32))

## [1.1.3](https://github.com/maxgfr/secretgate/compare/v1.1.2...v1.1.3) (2026-07-17)


### Bug Fixes

* **engine:** never flag the scanner's own rule database ([#2](https://github.com/maxgfr/secretgate/issues/2)) ([0d0d5d6](https://github.com/maxgfr/secretgate/commit/0d0d5d6126f7993772e69711b0f0780979be67d8))

## [1.1.2](https://github.com/maxgfr/secretgate/compare/v1.1.1...v1.1.2) (2026-07-13)


### Bug Fixes

* **opencode:** plugin bundle must export ONLY the plugin function ([6f51eaa](https://github.com/maxgfr/secretgate/commit/6f51eaa1f31f5702be192945f90ab7b2bfa09044))

## [1.1.1](https://github.com/maxgfr/secretgate/compare/v1.1.0...v1.1.1) (2026-07-13)


### Bug Fixes

* **install:** ship the OpenCode plugin bundle in the skill + make init/install fault-tolerant per agent ([390af62](https://github.com/maxgfr/secretgate/commit/390af622cc1b8526660db73b5a6951d9b915a1ed))

# [1.1.0](https://github.com/maxgfr/secretgate/compare/v1.0.1...v1.1.0) (2026-07-13)


### Features

* **security:** init command + close secret-leak paths found by adversarial audit ([3c44f1b](https://github.com/maxgfr/secretgate/commit/3c44f1b257452fa27771dcfc81e42c37866546aa))

## [1.0.1](https://github.com/maxgfr/secretgate/compare/v1.0.0...v1.0.1) (2026-07-13)


### Bug Fixes

* **ci:** use a high-entropy fake token in the Node-18 floor pipe smoke (low-entropy token was filtered by the entropy gate) ([657a368](https://github.com/maxgfr/secretgate/commit/657a368a469cc86648937ad5dc7af2f5db346e05)), closes [hi#entropy](https://github.com/hi/issues/entropy)

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
