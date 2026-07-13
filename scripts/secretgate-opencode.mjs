#!/usr/bin/env node

// src/config.ts
import { readFileSync as readFileSync2 } from "fs";
import { join as join2 } from "path";

// src/vault/vault.ts
import { randomBytes } from "crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "fs";
import { homedir } from "os";
import { join } from "path";

// src/vault/placeholder.ts
import { createHmac } from "crypto";
function placeholderFor(secret, salt, hexLen = 12) {
  const digest = createHmac("sha256", salt).update(secret).digest("hex");
  return `SECRETGATE_${digest.slice(0, hexLen)}`;
}
var PLACEHOLDER_RE = /SECRETGATE_[0-9a-f]{12,16}/g;

// src/vault/vault.ts
function defaultVaultHome() {
  return process.env.SECRETGATE_HOME ?? join(homedir(), ".secretgate");
}
function writeFileAtomic(path, content, mode) {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", mode);
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}
var Vault = class {
  home;
  vaultPath;
  saltValue;
  constructor(home = defaultVaultHome()) {
    this.home = home;
    this.vaultPath = join(home, "vault.json");
  }
  ensureHome() {
    mkdirSync(this.home, { recursive: true, mode: 448 });
  }
  salt() {
    if (this.saltValue) return this.saltValue;
    this.ensureHome();
    const saltPath = join(this.home, "salt");
    try {
      this.saltValue = readFileSync(saltPath, "utf8").trim();
    } catch {
      this.saltValue = randomBytes(32).toString("hex");
      writeFileAtomic(saltPath, this.saltValue, 384);
    }
    if (!this.saltValue) throw new Error(`empty salt file: ${saltPath}`);
    return this.saltValue;
  }
  read() {
    try {
      const parsed = JSON.parse(readFileSync(this.vaultPath, "utf8"));
      if (parsed && parsed.version === 1 && parsed.entries) return parsed;
    } catch {
    }
    return { version: 1, entries: {} };
  }
  // recordSecret is a read-merge-write cycle so concurrent hook processes
  // (multiple tool calls in flight) don't clobber each other's entries.
  recordSecret(secret, ruleId, source) {
    this.ensureHome();
    const salt = this.salt();
    const file = this.read();
    let placeholder = "";
    for (const hexLen of [12, 16]) {
      placeholder = placeholderFor(secret, salt, hexLen);
      const existing = file.entries[placeholder];
      if (!existing || existing.secret === secret) break;
    }
    const entry = file.entries[placeholder];
    if (entry && entry.secret === secret) {
      if (!entry.sources.includes(source)) {
        entry.sources.push(source);
        writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 384);
      }
      return placeholder;
    }
    file.entries[placeholder] = { secret, ruleId, firstSeen: (/* @__PURE__ */ new Date()).toISOString(), sources: [source] };
    writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 384);
    return placeholder;
  }
  secretFor(placeholder) {
    return this.read().entries[placeholder]?.secret;
  }
  list() {
    return Object.entries(this.read().entries).map(([placeholder, e]) => ({
      placeholder,
      ruleId: e.ruleId,
      firstSeen: e.firstSeen,
      sources: e.sources
    }));
  }
  clear() {
    this.ensureHome();
    writeFileAtomic(this.vaultPath, JSON.stringify({ version: 1, entries: {} }, null, 2), 384);
  }
};

// src/config.ts
function readJson(path) {
  try {
    return JSON.parse(readFileSync2(path, "utf8"));
  } catch {
    return void 0;
  }
}
function loadConfig(cwd) {
  const home = defaultVaultHome();
  const base = readJson(join2(home, "config.json")) ?? {};
  const allow = readJson(join2(home, "allowlist.json")) ?? {};
  const project = cwd ? readJson(join2(cwd, ".secretgate.json")) ?? {} : {};
  const merged = {
    sha256: [...allow.sha256 ?? [], ...project.allowlist?.sha256 ?? []],
    rules: [...allow.rules ?? [], ...project.allowlist?.rules ?? []],
    paths: [...allow.paths ?? [], ...project.allowlist?.paths ?? []]
  };
  return {
    restoreBash: base.restoreBash === true,
    hybrid: base.hybrid === "off" ? "off" : "auto",
    allowlist: merged
  };
}

// src/engine/allowlist.ts
import { createHash } from "crypto";
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function isAllowedValue(secret, allowlist) {
  if (!allowlist?.sha256?.length) return false;
  const h = sha256(secret);
  return allowlist.sha256.includes(h);
}
function isDisabledRule(ruleId, allowlist) {
  return allowlist?.rules?.includes(ruleId) ?? false;
}
function pathMatchesGlob(path, glob) {
  let re = "";
  let i = 0;
  while (i < glob.length) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 3;
        } else {
          re += ".*";
          i += 2;
        }
      } else {
        re += "[^/]*";
        i++;
      }
    } else if (c === "?") {
      re += "[^/]";
      i++;
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  return new RegExp(`^(?:${re})$`).test(path);
}
function isAllowedPath(path, allowlist) {
  if (!path || !allowlist?.paths?.length) return false;
  return allowlist.paths.some((g) => pathMatchesGlob(path, g));
}

// src/paths.ts
var SENSITIVE_GLOBS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  "**/.aws/**",
  "**/.ssh/**",
  "**/.kube/config",
  "**/.npmrc",
  "**/.netrc",
  "**/.docker/config.json",
  "**/credentials.json"
];
var EXEMPT_GLOBS = ["**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist", "**/.env.defaults", "**/*.pub"];
function sensitivePathMatch(path) {
  const normalized = path.replaceAll("\\", "/");
  if (EXEMPT_GLOBS.some((g) => pathMatchesGlob(normalized, g))) return void 0;
  return SENSITIVE_GLOBS.find((g) => pathMatchesGlob(normalized, g));
}
var READ_COMMANDS = /* @__PURE__ */ new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "xxd",
  "od",
  "strings",
  "hexdump",
  "nl",
  "tac",
  "base64",
  "sed",
  "awk",
  "grep",
  "rg",
  "printf",
  "print"
]);
function commandTouchesSensitivePath(command) {
  for (const segment of command.split(/[;\n]|&&|\|\||\||&/)) {
    const tokens = segment.trim().split(/\s+/);
    if (tokens.length === 0) continue;
    const cmd = (tokens[0] ?? "").replace(/^.*\//, "");
    if (!READ_COMMANDS.has(cmd)) continue;
    for (const raw of tokens.slice(1)) {
      if (raw.startsWith(">")) break;
      const token = raw.replace(/^['"`]+|['"`]+$/g, "").replace(/^~\//, "/home/x/");
      if (token.length < 2 || token.startsWith("-")) continue;
      const hit = sensitivePathMatch(token);
      if (hit) return token;
    }
  }
  return void 0;
}

// src/engine/entropy.ts
function shannonEntropy(s) {
  if (s.length === 0) return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// src/engine/luhn.ts
function luhnValid(input, options = {}) {
  const s = options.stripSeparators ? input.replace(/[ -]/g, "") : input;
  if (s.length === 0 || !/^\d+$/.test(s)) return false;
  let sum = 0;
  let double = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let digit = s.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

// src/engine/pragma.ts
var SAME_LINE = /pragma:\s*allowlist\s+secret|gitleaks:allow/;
var NEXT_LINE = /pragma:\s*allowlist\s+nextline\s+secret/;
function pragmaAllowedLines(text) {
  const allowed = /* @__PURE__ */ new Set();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (NEXT_LINE.test(line)) {
      allowed.add(i + 1);
    } else if (SAME_LINE.test(line)) {
      allowed.add(i);
    }
  }
  return allowed;
}

// src/engine/rules.gen.ts
var RULES = [
  {
    "id": "1password-secret-key",
    "regex": {
      "source": "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      "flags": ""
    },
    "keywords": [
      "a3-"
    ],
    "entropy": 3.8
  },
  {
    "id": "1password-service-account-token",
    "regex": {
      "source": "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
      "flags": ""
    },
    "keywords": [
      "ops_"
    ],
    "entropy": 4
  },
  {
    "id": "adafruit-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "adafruit"
    ]
  },
  {
    "id": "adobe-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "adobe"
    ],
    "entropy": 2
  },
  {
    "id": "adobe-client-secret",
    "regex": {
      "source": `\\b(p8e-[a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "p8e-"
    ],
    "entropy": 2
  },
  {
    "id": "age-secret-key",
    "regex": {
      "source": "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
      "flags": ""
    },
    "keywords": [
      "age-secret-key-1"
    ]
  },
  {
    "id": "airtable-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{17})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "airtable"
    ]
  },
  {
    "id": "airtable-personnal-access-token",
    "regex": {
      "source": "\\b(pat[[:alnum:]]{14}\\.[a-f0-9]{64})\\b",
      "flags": ""
    },
    "keywords": [
      "airtable"
    ]
  },
  {
    "id": "algolia-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "algolia"
    ]
  },
  {
    "id": "alibaba-access-key-id",
    "regex": {
      "source": `\\b(LTAI[a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "ltai"
    ],
    "entropy": 2
  },
  {
    "id": "alibaba-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "alibaba"
    ],
    "entropy": 2
  },
  {
    "id": "anthropic-admin-api-key",
    "regex": {
      "source": `\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sk-ant-admin01"
    ]
  },
  {
    "id": "anthropic-api-key",
    "regex": {
      "source": `\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sk-ant-api03"
    ]
  },
  {
    "id": "artifactory-api-key",
    "regex": {
      "source": "\\bAKCp[A-Za-z0-9]{69}\\b",
      "flags": ""
    },
    "keywords": [
      "akcp"
    ],
    "entropy": 4.5
  },
  {
    "id": "artifactory-reference-token",
    "regex": {
      "source": "\\bcmVmd[A-Za-z0-9]{59}\\b",
      "flags": ""
    },
    "keywords": [
      "cmvmd"
    ],
    "entropy": 4.5
  },
  {
    "id": "asana-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "asana"
    ]
  },
  {
    "id": "asana-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "asana"
    ]
  },
  {
    "id": "atlassian-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:(?:ATLASSIAN|[Aa]tlassian)|(?:CONFLUENCE|[Cc]onfluence)|(?:JIRA|[Jj]ira))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\\x60'"\\s;]|\\\\[nr]|$)|\\b(ATATT3[A-Za-z0-9_\\-=]{186})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "atlassian",
      "confluence",
      "jira",
      "atatt3"
    ],
    "entropy": 3.5
  },
  {
    "id": "authress-service-client-access-key",
    "regex": {
      "source": `\\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\\.[a-z0-9]{4,6}\\.(?:acc)[_-][a-z0-9-]{10,32}\\.[a-z0-9+/_=-]{30,120})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sc_",
      "ext_",
      "scauth_",
      "authress_"
    ],
    "entropy": 2
  },
  {
    "id": "aws-access-token",
    "regex": {
      "source": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
      "flags": ""
    },
    "keywords": [
      "a3t",
      "akia",
      "asia",
      "abia",
      "acca"
    ],
    "entropy": 3,
    "allowlists": [
      {
        "regexes": [
          {
            "source": ".+EXAMPLE$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "aws-amazon-bedrock-api-key-long-lived",
    "regex": {
      "source": `\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "absk"
    ],
    "entropy": 3
  },
  {
    "id": "aws-amazon-bedrock-api-key-short-lived",
    "regex": {
      "source": "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
      "flags": ""
    },
    "keywords": [
      "bedrock-api-key-"
    ],
    "entropy": 3
  },
  {
    "id": "azure-ad-client-secret",
    "regex": {
      "source": `(?:^|[\\\\'"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'"\\x60\\s<),])`,
      "flags": ""
    },
    "keywords": [
      "q~"
    ],
    "entropy": 3
  },
  {
    "id": "beamer-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "beamer"
    ]
  },
  {
    "id": "bitbucket-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bitbucket"
    ]
  },
  {
    "id": "bitbucket-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bitbucket"
    ]
  },
  {
    "id": "bittrex-access-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bittrex"
    ]
  },
  {
    "id": "bittrex-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bittrex"
    ]
  },
  {
    "id": "cisco-meraki-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "meraki"
    ],
    "entropy": 3
  },
  {
    "id": "clickhouse-cloud-api-secret-key",
    "regex": {
      "source": "\\b(4b1d[A-Za-z0-9]{38})\\b",
      "flags": ""
    },
    "keywords": [
      "4b1d"
    ],
    "entropy": 3
  },
  {
    "id": "clojars-api-token",
    "regex": {
      "source": "CLOJARS_[a-z0-9]{60}",
      "flags": "i"
    },
    "keywords": [
      "clojars_"
    ],
    "entropy": 2
  },
  {
    "id": "cloudflare-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "cloudflare"
    ],
    "entropy": 2
  },
  {
    "id": "cloudflare-global-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "cloudflare"
    ],
    "entropy": 2
  },
  {
    "id": "cloudflare-origin-ca-key",
    "regex": {
      "source": `\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "cloudflare",
      "v1.0-"
    ],
    "entropy": 2
  },
  {
    "id": "codecov-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "codecov"
    ]
  },
  {
    "id": "cohere-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "cohere",
      "co_api_key"
    ],
    "entropy": 4
  },
  {
    "id": "coinbase-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "coinbase"
    ]
  },
  {
    "id": "confluent-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "confluent"
    ]
  },
  {
    "id": "confluent-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "confluent"
    ]
  },
  {
    "id": "contentful-delivery-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "contentful"
    ]
  },
  {
    "id": "curl-auth-header",
    "regex": {
      "source": `\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:"(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))"|'(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|$)`,
      "flags": "i"
    },
    "keywords": [
      "curl"
    ],
    "entropy": 2.75
  },
  {
    "id": "curl-auth-user",
    "regex": {
      "source": `\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\\w\${}@.-]+)))(?:\\s|$)`,
      "flags": ""
    },
    "keywords": [
      "curl"
    ],
    "entropy": 2,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
            "flags": ""
          },
          {
            "source": `['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`,
            "flags": ""
          },
          {
            "source": "[^:]+:\\[[^]]+]",
            "flags": ""
          },
          {
            "source": `['"]?[^:]+['"]?:['"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['"]?`,
            "flags": ""
          },
          {
            "source": "\\$\\([^)]+\\):\\$\\([^)]+\\)",
            "flags": ""
          },
          {
            "source": `['"]?\\$?{{[^}]+}}['"]?:['"]?\\$?{{[^}]+}}['"]?`,
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "databricks-api-token",
    "regex": {
      "source": `\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "dapi"
    ],
    "entropy": 3
  },
  {
    "id": "datadog-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "datadog"
    ]
  },
  {
    "id": "defined-networking-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dnkey"
    ]
  },
  {
    "id": "digitalocean-access-token",
    "regex": {
      "source": `\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "doo_v1_"
    ],
    "entropy": 3
  },
  {
    "id": "digitalocean-pat",
    "regex": {
      "source": `\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "dop_v1_"
    ],
    "entropy": 3
  },
  {
    "id": "digitalocean-refresh-token",
    "regex": {
      "source": `\\b(dor_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dor_v1_"
    ]
  },
  {
    "id": "discord-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "discord"
    ]
  },
  {
    "id": "discord-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{18})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "discord"
    ],
    "entropy": 2
  },
  {
    "id": "discord-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "discord"
    ],
    "entropy": 2
  },
  {
    "id": "doppler-api-token",
    "regex": {
      "source": "dp\\.pt\\.[a-z0-9]{43}",
      "flags": "i"
    },
    "keywords": [
      "dp.pt."
    ],
    "entropy": 2
  },
  {
    "id": "droneci-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "droneci"
    ]
  },
  {
    "id": "dropbox-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{15})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dropbox"
    ]
  },
  {
    "id": "dropbox-long-lived-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dropbox"
    ]
  },
  {
    "id": "dropbox-short-lived-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dropbox"
    ]
  },
  {
    "id": "duffel-api-token",
    "regex": {
      "source": "duffel_(?:test|live)_[a-z0-9_\\-=]{43}",
      "flags": "i"
    },
    "keywords": [
      "duffel_"
    ],
    "entropy": 2
  },
  {
    "id": "dynatrace-api-token",
    "regex": {
      "source": "dt0c01\\.[a-z0-9]{24}\\.[a-z0-9]{64}",
      "flags": "i"
    },
    "keywords": [
      "dt0c01."
    ],
    "entropy": 4
  },
  {
    "id": "easypost-api-token",
    "regex": {
      "source": "\\bEZAK[a-z0-9]{54}\\b",
      "flags": "i"
    },
    "keywords": [
      "ezak"
    ],
    "entropy": 2
  },
  {
    "id": "easypost-test-api-token",
    "regex": {
      "source": "\\bEZTK[a-z0-9]{54}\\b",
      "flags": "i"
    },
    "keywords": [
      "eztk"
    ],
    "entropy": 2
  },
  {
    "id": "etsy-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:(?:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "etsy"
    ],
    "entropy": 3
  },
  {
    "id": "facebook-access-token",
    "regex": {
      "source": `\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "facebook"
    ],
    "entropy": 3
  },
  {
    "id": "facebook-page-access-token",
    "regex": {
      "source": `\\b(EAA[MC][a-z0-9]{100,})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "eaam",
      "eaac"
    ],
    "entropy": 4
  },
  {
    "id": "facebook-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "facebook"
    ],
    "entropy": 3
  },
  {
    "id": "fastly-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "fastly"
    ]
  },
  {
    "id": "finicity-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "finicity"
    ]
  },
  {
    "id": "finicity-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "finicity"
    ]
  },
  {
    "id": "finnhub-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "finnhub"
    ]
  },
  {
    "id": "flickr-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "flickr"
    ]
  },
  {
    "id": "flutterwave-encryption-key",
    "regex": {
      "source": "FLWSECK_TEST-[a-h0-9]{12}",
      "flags": "i"
    },
    "keywords": [
      "flwseck_test"
    ],
    "entropy": 2
  },
  {
    "id": "flutterwave-public-key",
    "regex": {
      "source": "FLWPUBK_TEST-[a-h0-9]{32}-X",
      "flags": "i"
    },
    "keywords": [
      "flwpubk_test"
    ],
    "entropy": 2
  },
  {
    "id": "flutterwave-secret-key",
    "regex": {
      "source": "FLWSECK_TEST-[a-h0-9]{32}-X",
      "flags": "i"
    },
    "keywords": [
      "flwseck_test"
    ],
    "entropy": 2
  },
  {
    "id": "flyio-access-token",
    "regex": {
      "source": `\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "fo1_",
      "fm1",
      "fm2_"
    ],
    "entropy": 4
  },
  {
    "id": "frameio-api-token",
    "regex": {
      "source": "fio-u-[a-z0-9\\-_=]{64}",
      "flags": "i"
    },
    "keywords": [
      "fio-u-"
    ]
  },
  {
    "id": "freemius-secret-key",
    "regex": {
      "source": `["']secret_key["']\\s*=>\\s*["'](sk_[\\S]{29})["']`,
      "flags": "i"
    },
    "keywords": [
      "secret_key"
    ],
    "scopePath": {
      "source": "\\.php$",
      "flags": "i"
    }
  },
  {
    "id": "freshbooks-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "freshbooks"
    ]
  },
  {
    "id": "gcp-api-key",
    "regex": {
      "source": `\\b(AIza[\\w-]{35})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "aiza"
    ],
    "entropy": 4,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
            "flags": ""
          },
          {
            "source": "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
            "flags": ""
          },
          {
            "source": "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
            "flags": ""
          },
          {
            "source": "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
            "flags": ""
          },
          {
            "source": "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
            "flags": ""
          },
          {
            "source": "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
            "flags": ""
          },
          {
            "source": "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
            "flags": ""
          },
          {
            "source": "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
            "flags": ""
          },
          {
            "source": "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
            "flags": ""
          },
          {
            "source": "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
            "flags": ""
          },
          {
            "source": "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
            "flags": ""
          },
          {
            "source": "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
            "flags": ""
          },
          {
            "source": "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
            "flags": ""
          },
          {
            "source": "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
            "flags": ""
          },
          {
            "source": "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
            "flags": ""
          },
          {
            "source": "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "generic-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:access|auth|(?:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "access",
      "api",
      "auth",
      "key",
      "credential",
      "creds",
      "passwd",
      "password",
      "secret",
      "token"
    ],
    "entropy": 3.5,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "^[a-zA-Z_.-]+$",
            "flags": ""
          }
        ]
      },
      {
        "regexTarget": "match",
        "regexes": [
          {
            "source": "(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\\.jsonwebtoken[ \\t]?:[ \\t]?[\\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?:(?:[A-Z_]+=\\n[A-Z_]+=|[a-z_]+=\\n[a-z_]+=)(?:\\n|$))|(?:(?:[A-Z.]+=\\n[A-Z.]+=|[a-z.]+=\\n[a-z.]+=)(?:\\n|$)))",
            "flags": "i"
          }
        ],
        "stopwords": [
          "000000",
          "6fe4476ee5a1832882e326b506d14126",
          "_ec2_",
          "aaaaaa",
          "about",
          "abstract",
          "academy",
          "acces",
          "account",
          "act-",
          "act.",
          "act_",
          "action",
          "active",
          "actively",
          "activity",
          "adapter",
          "add-",
          "add-on",
          "add.",
          "add_",
          "addon",
          "addres",
          "admin",
          "adobe",
          "advanced",
          "adventure",
          "agent",
          "agile",
          "air-",
          "air.",
          "air_",
          "ajax",
          "akka",
          "alert",
          "alfred",
          "algorithm",
          "all-",
          "all.",
          "all_",
          "alloy",
          "alpha",
          "amazon",
          "amqp",
          "analysi",
          "analytic",
          "analyzer",
          "android",
          "angular",
          "angularj",
          "animate",
          "animation",
          "another",
          "ansible",
          "answer",
          "ant-",
          "ant.",
          "ant_",
          "any-",
          "any.",
          "any_",
          "apache",
          "app-",
          "app.",
          "app_",
          "apple",
          "arch",
          "archive",
          "archived",
          "arduino",
          "array",
          "art-",
          "art.",
          "art_",
          "article",
          "asp-",
          "asp.",
          "asp_",
          "asset",
          "async",
          "atom",
          "attention",
          "audio",
          "audit",
          "aura",
          "auth",
          "author",
          "authorize",
          "auto",
          "automated",
          "automatic",
          "awesome",
          "aws_",
          "azure",
          "back",
          "backbone",
          "backend",
          "backup",
          "bar-",
          "bar.",
          "bar_",
          "base",
          "based",
          "bash",
          "basic",
          "batch",
          "been",
          "beer",
          "behavior",
          "being",
          "benchmark",
          "best",
          "beta",
          "better",
          "big-",
          "big.",
          "big_",
          "binary",
          "binding",
          "bit-",
          "bit.",
          "bit_",
          "bitcoin",
          "block",
          "blog",
          "board",
          "book",
          "bookmark",
          "boost",
          "boot",
          "bootstrap",
          "bosh",
          "bot-",
          "bot.",
          "bot_",
          "bower",
          "box-",
          "box.",
          "box_",
          "boxen",
          "bracket",
          "branch",
          "bridge",
          "browser",
          "brunch",
          "buffer",
          "bug-",
          "bug.",
          "bug_",
          "build",
          "builder",
          "building",
          "buildout",
          "buildpack",
          "built",
          "bundle",
          "busines",
          "but-",
          "but.",
          "but_",
          "button",
          "cache",
          "caching",
          "cakephp",
          "calendar",
          "call",
          "camera",
          "campfire",
          "can-",
          "can.",
          "can_",
          "canva",
          "captcha",
          "capture",
          "card",
          "carousel",
          "case",
          "cassandra",
          "cat-",
          "cat.",
          "cat_",
          "category",
          "center",
          "cento",
          "challenge",
          "change",
          "changelog",
          "channel",
          "chart",
          "chat",
          "cheat",
          "check",
          "checker",
          "chef",
          "ches",
          "chinese",
          "chosen",
          "chrome",
          "ckeditor",
          "clas",
          "classe",
          "classic",
          "clean",
          "cli-",
          "cli.",
          "cli_",
          "client",
          "clojure",
          "clone",
          "closure",
          "cloud",
          "club",
          "cluster",
          "cms-",
          "cms_",
          "coco",
          "code",
          "coding",
          "coffee",
          "color",
          "combination",
          "combo",
          "command",
          "commander",
          "comment",
          "commit",
          "common",
          "community",
          "compas",
          "compiler",
          "complete",
          "component",
          "composer",
          "computer",
          "computing",
          "con-",
          "con.",
          "con_",
          "concept",
          "conf",
          "config",
          "connect",
          "connector",
          "console",
          "contact",
          "container",
          "contao",
          "content",
          "contest",
          "context",
          "control",
          "convert",
          "converter",
          "conway'",
          "cookbook",
          "cookie",
          "cool",
          "copy",
          "cordova",
          "core",
          "couchbase",
          "couchdb",
          "countdown",
          "counter",
          "course",
          "craft",
          "crawler",
          "create",
          "creating",
          "creator",
          "credential",
          "crm-",
          "crm.",
          "crm_",
          "cros",
          "crud",
          "csv-",
          "csv.",
          "csv_",
          "cube",
          "cucumber",
          "cuda",
          "current",
          "currently",
          "custom",
          "daemon",
          "dark",
          "dart",
          "dash",
          "dashboard",
          "data",
          "database",
          "date",
          "day-",
          "day.",
          "day_",
          "dead",
          "debian",
          "debug",
          "debugger",
          "deck",
          "define",
          "del-",
          "del.",
          "del_",
          "delete",
          "demo",
          "deploy",
          "design",
          "designer",
          "desktop",
          "detection",
          "detector",
          "dev-",
          "dev.",
          "dev_",
          "develop",
          "developer",
          "device",
          "devise",
          "diff",
          "digital",
          "directive",
          "directory",
          "discovery",
          "display",
          "django",
          "dns-",
          "dns_",
          "doc-",
          "doc.",
          "doc_",
          "docker",
          "docpad",
          "doctrine",
          "document",
          "doe-",
          "doe.",
          "doe_",
          "dojo",
          "dom-",
          "dom.",
          "dom_",
          "domain",
          "don't",
          "done",
          "dot-",
          "dot.",
          "dot_",
          "dotfile",
          "download",
          "draft",
          "drag",
          "drill",
          "drive",
          "driven",
          "driver",
          "drop",
          "dropbox",
          "drupal",
          "dsl-",
          "dsl.",
          "dsl_",
          "dynamic",
          "easy",
          "ecdsa",
          "eclipse",
          "edit",
          "editing",
          "edition",
          "editor",
          "element",
          "emac",
          "email",
          "embed",
          "embedded",
          "ember",
          "emitter",
          "emulator",
          "encoding",
          "endpoint",
          "engine",
          "english",
          "enhanced",
          "entity",
          "entry",
          "env_",
          "episode",
          "erlang",
          "error",
          "espresso",
          "event",
          "evented",
          "example",
          "exchange",
          "exercise",
          "experiment",
          "expire",
          "exploit",
          "explorer",
          "export",
          "exporter",
          "expres",
          "ext-",
          "ext.",
          "ext_",
          "extended",
          "extension",
          "external",
          "extra",
          "extractor",
          "fabric",
          "facebook",
          "factory",
          "fake",
          "fast",
          "feature",
          "feed",
          "fewfwef",
          "ffmpeg",
          "field",
          "file",
          "filter",
          "find",
          "finder",
          "firefox",
          "firmware",
          "first",
          "fish",
          "fix-",
          "fix_",
          "flash",
          "flask",
          "flat",
          "flex",
          "flexible",
          "flickr",
          "flow",
          "fluent",
          "fluentd",
          "fluid",
          "folder",
          "font",
          "force",
          "foreman",
          "fork",
          "form",
          "format",
          "formatter",
          "forum",
          "foundry",
          "framework",
          "free",
          "friend",
          "friendly",
          "front-end",
          "frontend",
          "ftp-",
          "ftp.",
          "ftp_",
          "fuel",
          "full",
          "fun-",
          "fun.",
          "fun_",
          "func",
          "future",
          "gaia",
          "gallery",
          "game",
          "gateway",
          "gem-",
          "gem.",
          "gem_",
          "gen-",
          "gen.",
          "gen_",
          "general",
          "generator",
          "generic",
          "genetic",
          "get-",
          "get.",
          "get_",
          "getenv",
          "getting",
          "ghost",
          "gist",
          "git-",
          "git.",
          "git_",
          "github",
          "gitignore",
          "gitlab",
          "glas",
          "gmail",
          "gnome",
          "gnu-",
          "gnu.",
          "gnu_",
          "goal",
          "golang",
          "gollum",
          "good",
          "google",
          "gpu-",
          "gpu.",
          "gpu_",
          "gradle",
          "grail",
          "graph",
          "graphic",
          "great",
          "grid",
          "groovy",
          "group",
          "grunt",
          "guard",
          "gui-",
          "gui.",
          "gui_",
          "guide",
          "guideline",
          "gulp",
          "gwt-",
          "gwt.",
          "gwt_",
          "hack",
          "hackathon",
          "hacker",
          "hacking",
          "hadoop",
          "haml",
          "handler",
          "hardware",
          "has-",
          "has_",
          "hash",
          "haskell",
          "have",
          "haxe",
          "hello",
          "help",
          "helper",
          "here",
          "hero",
          "heroku",
          "high",
          "hipchat",
          "history",
          "home",
          "homebrew",
          "homepage",
          "hook",
          "host",
          "hosting",
          "hot-",
          "hot.",
          "hot_",
          "house",
          "how-",
          "how.",
          "how_",
          "html",
          "http",
          "hub-",
          "hub.",
          "hub_",
          "hubot",
          "human",
          "icon",
          "ide-",
          "ide.",
          "ide_",
          "idea",
          "identity",
          "idiomatic",
          "image",
          "impact",
          "import",
          "important",
          "importer",
          "impres",
          "index",
          "infinite",
          "info",
          "injection",
          "inline",
          "input",
          "inside",
          "inspector",
          "instagram",
          "install",
          "installer",
          "instant",
          "intellij",
          "interface",
          "internet",
          "interview",
          "into",
          "intro",
          "ionic",
          "iphone",
          "ipython",
          "irc-",
          "irc_",
          "iso-",
          "iso.",
          "iso_",
          "issue",
          "jade",
          "jasmine",
          "java",
          "jbos",
          "jekyll",
          "jenkin",
          "jetbrains",
          "job-",
          "job.",
          "job_",
          "joomla",
          "jpa-",
          "jpa.",
          "jpa_",
          "jquery",
          "json",
          "just",
          "kafka",
          "karma",
          "kata",
          "kernel",
          "keyboard",
          "kindle",
          "kit-",
          "kit.",
          "kit_",
          "kitchen",
          "knife",
          "koan",
          "kohana",
          "lab-",
          "lab.",
          "lab_",
          "lambda",
          "lamp",
          "language",
          "laravel",
          "last",
          "latest",
          "latex",
          "launcher",
          "layer",
          "layout",
          "lazy",
          "ldap",
          "leaflet",
          "league",
          "learn",
          "learning",
          "led-",
          "led.",
          "led_",
          "leetcode",
          "les-",
          "les.",
          "les_",
          "level",
          "leveldb",
          "lib-",
          "lib.",
          "lib_",
          "librarie",
          "library",
          "license",
          "life",
          "liferay",
          "light",
          "lightbox",
          "like",
          "line",
          "link",
          "linked",
          "linkedin",
          "linux",
          "lisp",
          "list",
          "lite",
          "little",
          "load",
          "loader",
          "local",
          "location",
          "lock",
          "log-",
          "log.",
          "log_",
          "logger",
          "logging",
          "logic",
          "login",
          "logstash",
          "longer",
          "look",
          "love",
          "lua-",
          "lua.",
          "lua_",
          "mac-",
          "mac.",
          "mac_",
          "machine",
          "made",
          "magento",
          "magic",
          "mail",
          "make",
          "maker",
          "making",
          "man-",
          "man.",
          "man_",
          "manage",
          "manager",
          "manifest",
          "manual",
          "map-",
          "map.",
          "map_",
          "mapper",
          "mapping",
          "markdown",
          "markup",
          "master",
          "math",
          "matrix",
          "maven",
          "md5",
          "mean",
          "media",
          "mediawiki",
          "meetup",
          "memcached",
          "memory",
          "menu",
          "merchant",
          "message",
          "messaging",
          "meta",
          "metadata",
          "meteor",
          "method",
          "metric",
          "micro",
          "middleman",
          "migration",
          "minecraft",
          "miner",
          "mini",
          "minimal",
          "mirror",
          "mit-",
          "mit.",
          "mit_",
          "mobile",
          "mocha",
          "mock",
          "mod-",
          "mod.",
          "mod_",
          "mode",
          "model",
          "modern",
          "modular",
          "module",
          "modx",
          "money",
          "mongo",
          "mongodb",
          "mongoid",
          "mongoose",
          "monitor",
          "monkey",
          "more",
          "motion",
          "moved",
          "movie",
          "mozilla",
          "mqtt",
          "mule",
          "multi",
          "multiple",
          "music",
          "mustache",
          "mvc-",
          "mvc.",
          "mvc_",
          "mysql",
          "nagio",
          "name",
          "native",
          "need",
          "neo-",
          "neo.",
          "neo_",
          "nest",
          "nested",
          "net-",
          "net.",
          "net_",
          "nette",
          "network",
          "new-",
          "new.",
          "new_",
          "next",
          "nginx",
          "ninja",
          "nlp-",
          "nlp.",
          "nlp_",
          "node",
          "nodej",
          "nosql",
          "not-",
          "not.",
          "not_",
          "note",
          "notebook",
          "notepad",
          "notice",
          "notifier",
          "now-",
          "now.",
          "now_",
          "number",
          "oauth",
          "object",
          "objective",
          "obsolete",
          "ocaml",
          "octopres",
          "official",
          "old-",
          "old.",
          "old_",
          "onboard",
          "online",
          "only",
          "open",
          "opencv",
          "opengl",
          "openshift",
          "openwrt",
          "option",
          "oracle",
          "org-",
          "org.",
          "org_",
          "origin",
          "original",
          "orm-",
          "orm.",
          "orm_",
          "osx-",
          "osx_",
          "our-",
          "our.",
          "our_",
          "out-",
          "out.",
          "out_",
          "output",
          "over",
          "overview",
          "own-",
          "own.",
          "own_",
          "pack",
          "package",
          "packet",
          "page",
          "panel",
          "paper",
          "paperclip",
          "para",
          "parallax",
          "parallel",
          "parse",
          "parser",
          "parsing",
          "particle",
          "party",
          "password",
          "patch",
          "path",
          "pattern",
          "payment",
          "paypal",
          "pdf-",
          "pdf.",
          "pdf_",
          "pebble",
          "people",
          "perl",
          "personal",
          "phalcon",
          "phoenix",
          "phone",
          "phonegap",
          "photo",
          "php-",
          "php.",
          "php_",
          "physic",
          "picker",
          "pipeline",
          "platform",
          "play",
          "player",
          "please",
          "plu-",
          "plu.",
          "plu_",
          "plug-in",
          "plugin",
          "plupload",
          "png-",
          "png.",
          "png_",
          "poker",
          "polyfill",
          "polymer",
          "pool",
          "pop-",
          "pop.",
          "pop_",
          "popcorn",
          "popup",
          "port",
          "portable",
          "portal",
          "portfolio",
          "post",
          "power",
          "powered",
          "powerful",
          "prelude",
          "pretty",
          "preview",
          "principle",
          "print",
          "pro-",
          "pro.",
          "pro_",
          "problem",
          "proc",
          "product",
          "profile",
          "profiler",
          "program",
          "progres",
          "project",
          "protocol",
          "prototype",
          "provider",
          "proxy",
          "public",
          "pull",
          "puppet",
          "pure",
          "purpose",
          "push",
          "pusher",
          "pyramid",
          "python",
          "quality",
          "query",
          "queue",
          "quick",
          "rabbitmq",
          "rack",
          "radio",
          "rail",
          "railscast",
          "random",
          "range",
          "raspberry",
          "rdf-",
          "rdf.",
          "rdf_",
          "react",
          "reactive",
          "read",
          "reader",
          "readme",
          "ready",
          "real",
          "real-time",
          "reality",
          "realtime",
          "recipe",
          "recorder",
          "red-",
          "red.",
          "red_",
          "reddit",
          "redi",
          "redmine",
          "reference",
          "refinery",
          "refresh",
          "registry",
          "related",
          "release",
          "remote",
          "rendering",
          "repo",
          "report",
          "request",
          "require",
          "required",
          "requirej",
          "research",
          "resource",
          "response",
          "resque",
          "rest",
          "restful",
          "resume",
          "reveal",
          "reverse",
          "review",
          "riak",
          "rich",
          "right",
          "ring",
          "robot",
          "role",
          "room",
          "router",
          "routing",
          "rpc-",
          "rpc.",
          "rpc_",
          "rpg-",
          "rpg.",
          "rpg_",
          "rspec",
          "ruby-",
          "ruby.",
          "ruby_",
          "rule",
          "run-",
          "run.",
          "run_",
          "runner",
          "running",
          "runtime",
          "rust",
          "rvm-",
          "rvm.",
          "rvm_",
          "salt",
          "sample",
          "sandbox",
          "sas-",
          "sas.",
          "sas_",
          "sbt-",
          "sbt.",
          "sbt_",
          "scala",
          "scalable",
          "scanner",
          "schema",
          "scheme",
          "school",
          "science",
          "scraper",
          "scratch",
          "screen",
          "script",
          "scroll",
          "scs-",
          "scs.",
          "scs_",
          "sdk-",
          "sdk.",
          "sdk_",
          "sdl-",
          "sdl.",
          "sdl_",
          "search",
          "secure",
          "security",
          "see-",
          "see.",
          "see_",
          "seed",
          "select",
          "selector",
          "selenium",
          "semantic",
          "sencha",
          "send",
          "sentiment",
          "serie",
          "server",
          "service",
          "session",
          "set-",
          "set.",
          "set_",
          "setting",
          "setup",
          "sha1",
          "sha2",
          "sha256",
          "share",
          "shared",
          "sharing",
          "sheet",
          "shell",
          "shield",
          "shipping",
          "shop",
          "shopify",
          "shortener",
          "should",
          "show",
          "showcase",
          "side",
          "silex",
          "simple",
          "simulator",
          "single",
          "site",
          "skeleton",
          "sketch",
          "skin",
          "slack",
          "slide",
          "slider",
          "slim",
          "small",
          "smart",
          "smtp",
          "snake",
          "snapshot",
          "snippet",
          "soap",
          "social",
          "socket",
          "software",
          "solarized",
          "solr",
          "solution",
          "solver",
          "some",
          "soon",
          "source",
          "space",
          "spark",
          "spatial",
          "spec",
          "sphinx",
          "spine",
          "spotify",
          "spree",
          "spring",
          "sprite",
          "sql-",
          "sql.",
          "sql_",
          "sqlite",
          "ssh-",
          "ssh.",
          "ssh_",
          "stack",
          "staging",
          "standard",
          "stanford",
          "start",
          "started",
          "starter",
          "startup",
          "stat",
          "statamic",
          "state",
          "static",
          "statistic",
          "statsd",
          "statu",
          "steam",
          "step",
          "still",
          "stm-",
          "stm.",
          "stm_",
          "storage",
          "store",
          "storm",
          "story",
          "strategy",
          "stream",
          "streaming",
          "string",
          "stripe",
          "structure",
          "studio",
          "study",
          "stuff",
          "style",
          "sublime",
          "sugar",
          "suite",
          "summary",
          "super",
          "support",
          "supported",
          "svg-",
          "svg.",
          "svg_",
          "svn-",
          "svn.",
          "svn_",
          "swagger",
          "swift",
          "switch",
          "switcher",
          "symfony",
          "symphony",
          "sync",
          "synopsi",
          "syntax",
          "system",
          "tab-",
          "tab.",
          "tab_",
          "table",
          "tag-",
          "tag.",
          "tag_",
          "talk",
          "target",
          "task",
          "tcp-",
          "tcp.",
          "tcp_",
          "tdd-",
          "tdd.",
          "tdd_",
          "team",
          "tech",
          "template",
          "term",
          "terminal",
          "testing",
          "tetri",
          "text",
          "textmate",
          "theme",
          "theory",
          "three",
          "thrift",
          "time",
          "timeline",
          "timer",
          "tiny",
          "tinymce",
          "tip-",
          "tip.",
          "tip_",
          "title",
          "todo",
          "todomvc",
          "token",
          "tool",
          "toolbox",
          "toolkit",
          "top-",
          "top.",
          "top_",
          "tornado",
          "touch",
          "tower",
          "tracker",
          "tracking",
          "traffic",
          "training",
          "transfer",
          "translate",
          "transport",
          "tree",
          "trello",
          "try-",
          "try.",
          "try_",
          "tumblr",
          "tut-",
          "tut.",
          "tut_",
          "tutorial",
          "tweet",
          "twig",
          "twitter",
          "type",
          "typo",
          "ubuntu",
          "uiview",
          "ultimate",
          "under",
          "unit",
          "unity",
          "universal",
          "unix",
          "update",
          "updated",
          "upgrade",
          "upload",
          "uploader",
          "uri-",
          "uri.",
          "uri_",
          "url-",
          "url.",
          "url_",
          "usage",
          "usb-",
          "usb.",
          "usb_",
          "use-",
          "use.",
          "use_",
          "used",
          "useful",
          "user",
          "using",
          "util",
          "utilitie",
          "utility",
          "vagrant",
          "validator",
          "value",
          "variou",
          "varnish",
          "version",
          "via-",
          "via.",
          "via_",
          "video",
          "view",
          "viewer",
          "vim-",
          "vim.",
          "vim_",
          "vimrc",
          "virtual",
          "vision",
          "visual",
          "vpn",
          "want",
          "warning",
          "watch",
          "watcher",
          "wave",
          "way-",
          "way.",
          "way_",
          "weather",
          "web-",
          "web_",
          "webapp",
          "webgl",
          "webhook",
          "webkit",
          "webrtc",
          "website",
          "websocket",
          "welcome",
          "what",
          "what'",
          "when",
          "where",
          "which",
          "why-",
          "why.",
          "why_",
          "widget",
          "wifi",
          "wiki",
          "win-",
          "win.",
          "win_",
          "window",
          "wip-",
          "wip.",
          "wip_",
          "within",
          "without",
          "wizard",
          "word",
          "wordpres",
          "work",
          "worker",
          "workflow",
          "working",
          "workshop",
          "world",
          "wrapper",
          "write",
          "writer",
          "writing",
          "written",
          "www-",
          "www.",
          "www_",
          "xamarin",
          "xcode",
          "xml-",
          "xml.",
          "xml_",
          "xmpp",
          "xxxxxx",
          "yahoo",
          "yaml",
          "yandex",
          "yeoman",
          "yet-",
          "yet.",
          "yet_",
          "yii-",
          "yii.",
          "yii_",
          "youtube",
          "yui-",
          "yui.",
          "yui_",
          "zend",
          "zero",
          "zip-",
          "zip.",
          "zip_",
          "zsh-",
          "zsh.",
          "zsh_"
        ]
      },
      {
        "regexTarget": "line",
        "regexes": [
          {
            "source": "--mount=type=secret,",
            "flags": ""
          },
          {
            "source": `import[ \\t]+{[ \\t\\w,]+}[ \\t]+from[ \\t]+['"][^'"]+['"]`,
            "flags": ""
          }
        ]
      },
      {
        "condition": "AND",
        "regexTarget": "line",
        "regexes": [
          {
            "source": 'LICENSE[^=]*=\\s*"[^"]+',
            "flags": ""
          },
          {
            "source": 'LIC_FILES_CHKSUM[^=]*=\\s*"[^"]+',
            "flags": ""
          },
          {
            "source": 'SRC[^=]*=\\s*"[a-zA-Z0-9]+',
            "flags": ""
          }
        ],
        "paths": [
          {
            "source": "\\.bb$",
            "flags": ""
          },
          {
            "source": "\\.bbappend$",
            "flags": ""
          },
          {
            "source": "\\.bbclass$",
            "flags": ""
          },
          {
            "source": "\\.inc$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "github-app-token",
    "regex": {
      "source": "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "ghu_",
      "ghs_"
    ],
    "entropy": 3,
    "allowlists": [
      {
        "paths": [
          {
            "source": "(?:^|/)@octokit/auth-token/README\\.md$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "github-fine-grained-pat",
    "regex": {
      "source": "github_pat_\\w{82}",
      "flags": ""
    },
    "keywords": [
      "github_pat_"
    ],
    "entropy": 3
  },
  {
    "id": "github-oauth",
    "regex": {
      "source": "gho_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "gho_"
    ],
    "entropy": 3
  },
  {
    "id": "github-pat",
    "regex": {
      "source": "ghp_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "ghp_"
    ],
    "entropy": 3,
    "allowlists": [
      {
        "paths": [
          {
            "source": "(?:^|/)@octokit/auth-token/README\\.md$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "github-refresh-token",
    "regex": {
      "source": "ghr_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "ghr_"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-cicd-job-token",
    "regex": {
      "source": "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
      "flags": ""
    },
    "keywords": [
      "glcbt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-deploy-token",
    "regex": {
      "source": "gldt-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "gldt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-feature-flag-client-token",
    "regex": {
      "source": "glffct-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glffct-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-feed-token",
    "regex": {
      "source": "glft-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glft-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-incoming-mail-token",
    "regex": {
      "source": "glimt-[0-9a-zA-Z_\\-]{25}",
      "flags": ""
    },
    "keywords": [
      "glimt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-kubernetes-agent-token",
    "regex": {
      "source": "glagent-[0-9a-zA-Z_\\-]{50}",
      "flags": ""
    },
    "keywords": [
      "glagent-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-oauth-app-secret",
    "regex": {
      "source": "gloas-[0-9a-zA-Z_\\-]{64}",
      "flags": ""
    },
    "keywords": [
      "gloas-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-pat",
    "regex": {
      "source": "glpat-[\\w-]{20}",
      "flags": ""
    },
    "keywords": [
      "glpat-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-pat-routable",
    "regex": {
      "source": "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "flags": ""
    },
    "keywords": [
      "glpat-"
    ],
    "entropy": 4
  },
  {
    "id": "gitlab-ptt",
    "regex": {
      "source": "glptt-[0-9a-f]{40}",
      "flags": ""
    },
    "keywords": [
      "glptt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-rrt",
    "regex": {
      "source": "GR1348941[\\w-]{20}",
      "flags": ""
    },
    "keywords": [
      "gr1348941"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-runner-authentication-token",
    "regex": {
      "source": "glrt-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glrt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-runner-authentication-token-routable",
    "regex": {
      "source": "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "flags": ""
    },
    "keywords": [
      "glrt-"
    ],
    "entropy": 4
  },
  {
    "id": "gitlab-scim-token",
    "regex": {
      "source": "glsoat-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glsoat-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-session-cookie",
    "regex": {
      "source": "_gitlab_session=[0-9a-z]{32}",
      "flags": ""
    },
    "keywords": [
      "_gitlab_session="
    ],
    "entropy": 3
  },
  {
    "id": "gitter-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "gitter"
    ]
  },
  {
    "id": "gocardless-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(live_[a-z0-9\\-_=]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "live_",
      "gocardless"
    ]
  },
  {
    "id": "grafana-api-key",
    "regex": {
      "source": `\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "eyjrijoi"
    ],
    "entropy": 3
  },
  {
    "id": "grafana-cloud-api-token",
    "regex": {
      "source": `\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "glc_"
    ],
    "entropy": 3
  },
  {
    "id": "grafana-service-account-token",
    "regex": {
      "source": `\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "glsa_"
    ],
    "entropy": 3
  },
  {
    "id": "harness-api-key",
    "regex": {
      "source": "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
      "flags": ""
    },
    "keywords": [
      "pat.",
      "sat."
    ]
  },
  {
    "id": "hashicorp-tf-api-token",
    "regex": {
      "source": "[a-z0-9]{14}\\.(?:atlasv1)\\.[a-z0-9\\-_=]{60,70}",
      "flags": "i"
    },
    "keywords": [
      "atlasv1"
    ],
    "entropy": 3.5
  },
  {
    "id": "hashicorp-tf-password",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}("[a-z0-9=_\\-]{8,20}")(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "administrator_login_password",
      "password"
    ],
    "entropy": 2,
    "scopePath": {
      "source": "\\.(?:tf|hcl)$",
      "flags": "i"
    }
  },
  {
    "id": "heroku-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "heroku"
    ]
  },
  {
    "id": "heroku-api-key-v2",
    "regex": {
      "source": `\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "hrku-aa"
    ],
    "entropy": 4
  },
  {
    "id": "hubspot-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "hubspot"
    ]
  },
  {
    "id": "huggingface-access-token",
    "regex": {
      "source": `\\b(hf_(?:[a-z]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "hf_"
    ],
    "entropy": 2
  },
  {
    "id": "huggingface-organization-api-token",
    "regex": {
      "source": `\\b(api_org_(?:[a-z]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "api_org_"
    ],
    "entropy": 2
  },
  {
    "id": "infracost-api-token",
    "regex": {
      "source": `\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "ico-"
    ],
    "entropy": 3
  },
  {
    "id": "intercom-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "intercom"
    ]
  },
  {
    "id": "intra42-client-secret",
    "regex": {
      "source": `\\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "intra",
      "s-s4t2ud-",
      "s-s4t2af-"
    ],
    "entropy": 3
  },
  {
    "id": "jfrog-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{73})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "jfrog",
      "artifactory",
      "bintray",
      "xray"
    ]
  },
  {
    "id": "jfrog-identity-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "jfrog",
      "artifactory",
      "bintray",
      "xray"
    ]
  },
  {
    "id": "jwt",
    "regex": {
      "source": `\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "ey"
    ],
    "entropy": 3
  },
  {
    "id": "jwt-base64",
    "regex": {
      "source": "\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
      "flags": ""
    },
    "keywords": [
      "zxlk"
    ],
    "entropy": 2
  },
  {
    "id": "kraken-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:kraken)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9\\/=_\\+\\-]{80,90})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "kraken"
    ]
  },
  {
    "id": "kubernetes-secret-yaml",
    "regex": {
      "source": `(?:\\bkind:[ \\t]*["']?\\bsecret\\b["']?(?:[\\s\\S]){0,200}?\\bdata:(?:[\\s\\S]){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|''))|\\bdata:(?:[\\s\\S]){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|''))(?:[\\s\\S]){0,200}?\\bkind:[ \\t]*["']?\\bsecret\\b["']?)`,
      "flags": "i"
    },
    "keywords": [
      "secret"
    ],
    "scopePath": {
      "source": "\\.ya?ml$",
      "flags": "i"
    },
    "allowlists": [
      {
        "regexes": [
          {
            "source": `[\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:\\{\\{[ \\t\\w"|$:=,.-]+}}|""|'')`,
            "flags": ""
          }
        ]
      },
      {
        "regexTarget": "match",
        "regexes": [
          {
            "source": "(kind:(?:[\\s\\S])+\\n---\\n(?:[\\s\\S])+\\bdata:|data:(?:[\\s\\S])+\\n---\\n(?:[\\s\\S])+\\bkind:)",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "kucoin-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "kucoin"
    ]
  },
  {
    "id": "kucoin-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "kucoin"
    ]
  },
  {
    "id": "launchdarkly-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "launchdarkly"
    ]
  },
  {
    "id": "linear-api-key",
    "regex": {
      "source": "lin_api_[a-z0-9]{40}",
      "flags": "i"
    },
    "keywords": [
      "lin_api_"
    ],
    "entropy": 2
  },
  {
    "id": "linear-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "linear"
    ],
    "entropy": 2
  },
  {
    "id": "linkedin-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{14})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "linkedin",
      "linked_in",
      "linked-in"
    ],
    "entropy": 2
  },
  {
    "id": "linkedin-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "linkedin",
      "linked_in",
      "linked-in"
    ],
    "entropy": 2
  },
  {
    "id": "lob-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "test_",
      "live_"
    ]
  },
  {
    "id": "lob-pub-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "test_pub",
      "live_pub",
      "_pub"
    ]
  },
  {
    "id": "looker-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "looker"
    ]
  },
  {
    "id": "looker-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "looker"
    ]
  },
  {
    "id": "mailchimp-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailchimp"
    ]
  },
  {
    "id": "mailgun-private-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailgun"
    ]
  },
  {
    "id": "mailgun-pub-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailgun"
    ]
  },
  {
    "id": "mailgun-signing-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailgun"
    ]
  },
  {
    "id": "mapbox-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mapbox"
    ]
  },
  {
    "id": "mattermost-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mattermost"
    ]
  },
  {
    "id": "maxmind-license-key",
    "regex": {
      "source": `\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "_mmk"
    ],
    "entropy": 4
  },
  {
    "id": "messagebird-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "messagebird",
      "message-bird",
      "message_bird"
    ]
  },
  {
    "id": "messagebird-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "messagebird",
      "message-bird",
      "message_bird"
    ]
  },
  {
    "id": "microsoft-teams-webhook",
    "regex": {
      "source": "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
      "flags": ""
    },
    "keywords": [
      "webhook.office.com",
      "webhookb2",
      "incomingwebhook"
    ]
  },
  {
    "id": "netlify-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "netlify"
    ]
  },
  {
    "id": "new-relic-browser-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nrjs-"
    ]
  },
  {
    "id": "new-relic-insert-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nrii-"
    ]
  },
  {
    "id": "new-relic-user-api-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "new-relic",
      "newrelic",
      "new_relic"
    ]
  },
  {
    "id": "new-relic-user-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nrak"
    ]
  },
  {
    "id": "notion-api-token",
    "regex": {
      "source": `\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "ntn_"
    ],
    "entropy": 4
  },
  {
    "id": "npm-access-token",
    "regex": {
      "source": `\\b(npm_[a-z0-9]{36})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "npm_"
    ],
    "entropy": 2
  },
  {
    "id": "nuget-config-password",
    "regex": {
      "source": '<add key=\\"(?:(?:ClearText)?Password)\\"\\s*value=\\"(.{8,})\\"\\s*/>',
      "flags": "i"
    },
    "keywords": [
      "<add key="
    ],
    "entropy": 1,
    "scopePath": {
      "source": "nuget\\.config$",
      "flags": "i"
    },
    "allowlists": [
      {
        "regexes": [
          {
            "source": "33f!!lloppa",
            "flags": ""
          },
          {
            "source": "hal\\+9ooo_da!sY",
            "flags": ""
          },
          {
            "source": "^\\%\\S.*\\%$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "nytimes-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nytimes",
      "new-york-times",
      "newyorktimes"
    ]
  },
  {
    "id": "octopus-deploy-api-key",
    "regex": {
      "source": `\\b(API-[A-Z0-9]{26})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "api-"
    ],
    "entropy": 3
  },
  {
    "id": "okta-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "okta"
    ],
    "entropy": 4
  },
  {
    "id": "openai-api-key",
    "regex": {
      "source": `\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "t3blbkfj"
    ],
    "entropy": 3
  },
  {
    "id": "openshift-user-token",
    "regex": {
      "source": "\\b(sha256~[\\w-]{43})(?:[^\\w-]|$)",
      "flags": ""
    },
    "keywords": [
      "sha256~"
    ],
    "entropy": 3.5
  },
  {
    "id": "perplexity-api-key",
    "regex": {
      "source": `\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$|\\b)`,
      "flags": ""
    },
    "keywords": [
      "pplx-"
    ],
    "entropy": 4
  },
  {
    "id": "plaid-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "plaid"
    ]
  },
  {
    "id": "plaid-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "plaid"
    ],
    "entropy": 3.5
  },
  {
    "id": "plaid-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "plaid"
    ],
    "entropy": 3.5
  },
  {
    "id": "planetscale-api-token",
    "regex": {
      "source": `\\b(pscale_tkn_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "pscale_tkn_"
    ],
    "entropy": 3
  },
  {
    "id": "planetscale-oauth-token",
    "regex": {
      "source": `\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "pscale_oauth_"
    ],
    "entropy": 3
  },
  {
    "id": "planetscale-password",
    "regex": {
      "source": `\\b(pscale_pw_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "pscale_pw_"
    ],
    "entropy": 3
  },
  {
    "id": "postman-api-token",
    "regex": {
      "source": `\\b(PMAK-[a-f0-9]{24}\\-[a-f0-9]{34})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "pmak-"
    ],
    "entropy": 3
  },
  {
    "id": "prefect-api-token",
    "regex": {
      "source": `\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "pnu_"
    ],
    "entropy": 2
  },
  {
    "id": "private-key",
    "regex": {
      "source": "-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----",
      "flags": "i"
    },
    "keywords": [
      "-----begin"
    ]
  },
  {
    "id": "privateai-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "privateai",
      "private_ai",
      "private-ai"
    ],
    "entropy": 3
  },
  {
    "id": "pulumi-api-token",
    "regex": {
      "source": `\\b(pul-[a-f0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "pul-"
    ],
    "entropy": 2
  },
  {
    "id": "pypi-upload-token",
    "regex": {
      "source": "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
      "flags": ""
    },
    "keywords": [
      "pypi-ageichlwas5vcmc"
    ],
    "entropy": 3
  },
  {
    "id": "rapidapi-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{50})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "rapidapi"
    ]
  },
  {
    "id": "readme-api-token",
    "regex": {
      "source": `\\b(rdme_[a-z0-9]{70})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "rdme_"
    ],
    "entropy": 2
  },
  {
    "id": "rubygems-api-token",
    "regex": {
      "source": `\\b(rubygems_[a-f0-9]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "rubygems_"
    ],
    "entropy": 2
  },
  {
    "id": "scalingo-api-token",
    "regex": {
      "source": `\\b(tk-us-[\\w-]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "tk-us-"
    ],
    "entropy": 2
  },
  {
    "id": "sendbird-access-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sendbird"
    ]
  },
  {
    "id": "sendbird-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sendbird"
    ]
  },
  {
    "id": "sendgrid-api-token",
    "regex": {
      "source": `\\b(SG\\.[a-z0-9=_\\-\\.]{66})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sg."
    ],
    "entropy": 2
  },
  {
    "id": "sendinblue-api-token",
    "regex": {
      "source": `\\b(xkeysib-[a-f0-9]{64}\\-[a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "xkeysib-"
    ],
    "entropy": 2
  },
  {
    "id": "sentry-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sentry"
    ],
    "entropy": 3
  },
  {
    "id": "sentry-org-token",
    "regex": {
      "source": "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|$)",
      "flags": ""
    },
    "keywords": [
      "sntrys_eyjpyxqio"
    ],
    "entropy": 4.5
  },
  {
    "id": "sentry-user-token",
    "regex": {
      "source": `\\b(sntryu_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sntryu_"
    ],
    "entropy": 3.5
  },
  {
    "id": "settlemint-application-access-token",
    "regex": {
      "source": `\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sm_aat"
    ],
    "entropy": 3
  },
  {
    "id": "settlemint-personal-access-token",
    "regex": {
      "source": `\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sm_pat"
    ],
    "entropy": 3
  },
  {
    "id": "settlemint-service-access-token",
    "regex": {
      "source": `\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sm_sat"
    ],
    "entropy": 3
  },
  {
    "id": "shippo-api-token",
    "regex": {
      "source": `\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "shippo_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-access-token",
    "regex": {
      "source": "shpat_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shpat_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-custom-access-token",
    "regex": {
      "source": "shpca_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shpca_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-private-app-access-token",
    "regex": {
      "source": "shppa_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shppa_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-shared-secret",
    "regex": {
      "source": "shpss_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shpss_"
    ],
    "entropy": 2
  },
  {
    "id": "sidekiq-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bundle_enterprise__contribsys__com",
      "bundle_gems__contribsys__com"
    ]
  },
  {
    "id": "sidekiq-sensitive-url",
    "regex": {
      "source": "\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)",
      "flags": "i"
    },
    "keywords": [
      "gems.contribsys.com",
      "enterprise.contribsys.com"
    ]
  },
  {
    "id": "slack-app-token",
    "regex": {
      "source": "xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+",
      "flags": "i"
    },
    "keywords": [
      "xapp"
    ],
    "entropy": 2
  },
  {
    "id": "slack-bot-token",
    "regex": {
      "source": "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
      "flags": ""
    },
    "keywords": [
      "xoxb"
    ],
    "entropy": 3
  },
  {
    "id": "slack-config-access-token",
    "regex": {
      "source": "xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}",
      "flags": "i"
    },
    "keywords": [
      "xoxe.xoxb-",
      "xoxe.xoxp-"
    ],
    "entropy": 2
  },
  {
    "id": "slack-config-refresh-token",
    "regex": {
      "source": "xoxe-\\d-[A-Z0-9]{146}",
      "flags": "i"
    },
    "keywords": [
      "xoxe-"
    ],
    "entropy": 2
  },
  {
    "id": "slack-legacy-bot-token",
    "regex": {
      "source": "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
      "flags": ""
    },
    "keywords": [
      "xoxb"
    ],
    "entropy": 2
  },
  {
    "id": "slack-legacy-token",
    "regex": {
      "source": "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
      "flags": ""
    },
    "keywords": [
      "xoxo",
      "xoxs"
    ],
    "entropy": 2
  },
  {
    "id": "slack-legacy-workspace-token",
    "regex": {
      "source": "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
      "flags": ""
    },
    "keywords": [
      "xoxa",
      "xoxr"
    ],
    "entropy": 2
  },
  {
    "id": "slack-user-token",
    "regex": {
      "source": "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
      "flags": ""
    },
    "keywords": [
      "xoxp-",
      "xoxe-"
    ],
    "entropy": 2
  },
  {
    "id": "slack-webhook-url",
    "regex": {
      "source": "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
      "flags": ""
    },
    "keywords": [
      "hooks.slack.com"
    ]
  },
  {
    "id": "snyk-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "snyk"
    ]
  },
  {
    "id": "sonar-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sonar"
    ],
    "secretGroup": 2
  },
  {
    "id": "sourcegraph-access-token",
    "regex": {
      "source": `\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sgp_",
      "sourcegraph"
    ],
    "entropy": 3
  },
  {
    "id": "square-access-token",
    "regex": {
      "source": `\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sq0atp-",
      "eaaa"
    ],
    "entropy": 2
  },
  {
    "id": "squarespace-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "squarespace"
    ]
  },
  {
    "id": "stripe-access-token",
    "regex": {
      "source": `\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sk_test",
      "sk_live",
      "sk_prod",
      "rk_test",
      "rk_live",
      "rk_prod"
    ],
    "entropy": 2
  },
  {
    "id": "sumologic-access-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sumo"
    ],
    "entropy": 3
  },
  {
    "id": "sumologic-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sumo"
    ],
    "entropy": 3
  },
  {
    "id": "telegram-bot-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{5,16}:(?:A)[a-z0-9_\\-]{34})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "telegr"
    ]
  },
  {
    "id": "travisci-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "travis"
    ]
  },
  {
    "id": "twilio-api-key",
    "regex": {
      "source": "SK[0-9a-fA-F]{32}",
      "flags": ""
    },
    "keywords": [
      "sk"
    ],
    "entropy": 3
  },
  {
    "id": "twitch-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitch"
    ]
  },
  {
    "id": "twitter-access-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-api-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-bearer-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "typeform-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "tfp_"
    ]
  },
  {
    "id": "vault-batch-token",
    "regex": {
      "source": `\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "hvb."
    ],
    "entropy": 4
  },
  {
    "id": "vault-service-token",
    "regex": {
      "source": `\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?:[a-z0-9]{24})))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "hvs.",
      "s."
    ],
    "entropy": 3.5,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "s\\.[A-Za-z]{24}",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "yandex-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "yandex"
    ]
  },
  {
    "id": "yandex-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "yandex"
    ]
  },
  {
    "id": "yandex-aws-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "yandex"
    ]
  },
  {
    "id": "zendesk-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "zendesk"
    ]
  }
];
var GLOBAL_ALLOWLIST = {
  "paths": [
    "gitleaks\\.toml",
    "\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
    "\\.(?:eot|[ot]tf|woff2?)$",
    "\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
    "go\\.(?:mod|sum|work(?:\\.sum)?)$",
    "(?:^|/)vendor/modules\\.txt$",
    "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$",
    "(?:^|/)gradlew(?:\\.bat)?$",
    "(?:^|/)gradle\\.lockfile$",
    "(?:^|/)mvnw(?:\\.cmd)?$",
    "(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$",
    "(?:^|/)node_modules(?:/.*)?$",
    "(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$",
    "(?:^|/)bower_components(?:/.*)?$",
    "(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$",
    "(?:^|/)javascript\\.json$",
    "(?:^|/)(?:Pipfile|poetry)\\.lock$",
    "(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
    "(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$",
    "(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$",
    "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$",
    "\\.gem$",
    "verification-metadata\\.xml",
    "Database.refactorlog",
    "(?:^|/)\\.git$"
  ],
  "regexes": [
    {
      "source": "^true|false|null$",
      "flags": "i"
    },
    {
      "source": "^(?:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$",
      "flags": "i"
    },
    {
      "source": "^\\$(?:\\d+|{\\d+})$",
      "flags": ""
    },
    {
      "source": "^\\$(?:[A-Z_]+|[a-z_]+)$",
      "flags": ""
    },
    {
      "source": "^\\${(?:[A-Z_]+|[a-z_]+)}$",
      "flags": ""
    },
    {
      "source": "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$",
      "flags": ""
    },
    {
      "source": `^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w "'&./=|]*)[ \\t]*}}$`,
      "flags": ""
    },
    {
      "source": "^%(?:[A-Z_]+|[a-z_]+)%$",
      "flags": ""
    },
    {
      "source": "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$",
      "flags": ""
    },
    {
      "source": "^\\{\\d{0,2}}$",
      "flags": ""
    },
    {
      "source": "^@(?:[A-Z_]+|[a-z_]+)@$",
      "flags": ""
    },
    {
      "source": "^/Users/[a-z0-9]+/[\\w .-/]+$",
      "flags": "i"
    },
    {
      "source": "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$",
      "flags": ""
    }
  ],
  "stopwords": [
    "014df517-39d1-4453-b7b3-9930c563627c",
    "abcdefghijklmnopqrstuvwxyz"
  ]
};

// src/engine/scanner.ts
var PLACEHOLDER_ONLY = /^SECRETGATE_[0-9a-f]{12,16}$/;
function compileAllowlist(a) {
  return {
    condition: a.condition === "AND" ? "AND" : "OR",
    regexTarget: a.regexTarget ?? "secret",
    regexes: (a.regexes ?? []).map((r) => new RegExp(r.source, r.flags)),
    stopwords: a.stopwords ?? [],
    paths: (a.paths ?? []).map((r) => new RegExp(r.source, r.flags))
  };
}
var IIN = /^(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$/;
var BUILTIN_RULES = [
  {
    id: "credit-card-number",
    re: /(?<![\d-])(\d(?:[ -]?\d){12,18})(?![\d-])/dg,
    keywords: [],
    allowlists: [],
    post: (secret) => {
      const digits = secret.replace(/[ -]/g, "");
      return IIN.test(digits) && luhnValid(digits);
    }
  }
];
var COMPILED = [
  ...RULES.map((r) => ({
    id: r.id,
    re: new RegExp(r.regex.source, r.regex.flags.includes("g") ? r.regex.flags + "d" : r.regex.flags + "dg"),
    entropy: r.entropy,
    secretGroup: r.secretGroup,
    keywords: r.keywords,
    allowlists: (r.allowlists ?? []).map(compileAllowlist),
    scope: r.scopePath ? new RegExp(r.scopePath.source, r.scopePath.flags) : void 0
  })),
  ...BUILTIN_RULES
];
var GLOBAL_PATHS = GLOBAL_ALLOWLIST.paths.map((p) => new RegExp(p));
var GLOBAL_REGEXES = GLOBAL_ALLOWLIST.regexes.map((r) => new RegExp(r.source, r.flags));
var GLOBAL_STOPWORDS = GLOBAL_ALLOWLIST.stopwords;
function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}
function lineAt(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = lo + hi + 1 >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}
function lineText(text, starts, line) {
  const start = starts[line];
  const end = line + 1 < starts.length ? starts[line + 1] - 1 : text.length;
  return text.slice(start, end);
}
function allowlistMatches(a, secret, target, sourcePath) {
  const checks = [];
  if (a.regexes.length > 0) checks.push(a.regexes.some((re) => re.test(target)));
  if (a.stopwords.length > 0) {
    const lowerSecret = secret.toLowerCase();
    checks.push(a.stopwords.some((s) => lowerSecret.includes(s)));
  }
  if (a.paths.length > 0) checks.push(sourcePath !== void 0 && a.paths.some((re) => re.test(sourcePath)));
  if (checks.length === 0) return false;
  return a.condition === "AND" ? checks.every(Boolean) : checks.some(Boolean);
}
function pickSecret(match, secretGroup) {
  const indices = match.indices;
  if (secretGroup && secretGroup > 0 && match[secretGroup] !== void 0) {
    const [s2, e2] = indices[secretGroup];
    return { secret: match[secretGroup], start: s2, end: e2 };
  }
  for (let g = 1; g < match.length; g++) {
    if (match[g] !== void 0 && match[g].length > 0) {
      const [s2, e2] = indices[g];
      return { secret: match[g], start: s2, end: e2 };
    }
  }
  const [s, e] = indices[0];
  return { secret: match[0], start: s, end: e };
}
function scan(text, cfg = {}) {
  if (text.length === 0) return [];
  if (cfg.sourcePath) {
    if (GLOBAL_PATHS.some((re) => re.test(cfg.sourcePath))) return [];
    if (isAllowedPath(cfg.sourcePath, cfg.allowlist)) return [];
  }
  const lower = text.toLowerCase();
  const starts = lineStarts(text);
  const pragmaLines = pragmaAllowedLines(text);
  const findings = [];
  for (const rule of COMPILED) {
    if (isDisabledRule(rule.id, cfg.allowlist)) continue;
    if (rule.scope && cfg.sourcePath && !rule.scope.test(cfg.sourcePath)) continue;
    if (rule.keywords.length > 0 && !rule.keywords.some((k) => lower.includes(k))) continue;
    rule.re.lastIndex = 0;
    for (const match of text.matchAll(rule.re)) {
      const { secret, start, end } = pickSecret(match, rule.secretGroup);
      if (secret.length === 0) continue;
      if (PLACEHOLDER_ONLY.test(secret)) continue;
      if (rule.post && !rule.post(secret)) continue;
      const entropy = shannonEntropy(secret);
      if (rule.entropy !== void 0 && entropy <= rule.entropy) continue;
      const line = lineAt(starts, start);
      if (pragmaLines.has(line)) continue;
      const fullMatch = match[0];
      let allowed = false;
      for (const a of rule.allowlists) {
        const target = a.regexTarget === "match" ? fullMatch : a.regexTarget === "line" ? lineText(text, starts, line) : secret;
        if (allowlistMatches(a, secret, target, cfg.sourcePath)) {
          allowed = true;
          break;
        }
      }
      if (allowed) continue;
      if (GLOBAL_REGEXES.length > 0 && GLOBAL_REGEXES.some((re) => re.test(secret))) continue;
      if (GLOBAL_STOPWORDS.length > 0 && GLOBAL_STOPWORDS.some((s) => secret.toLowerCase().includes(s))) continue;
      if (isAllowedValue(secret, cfg.allowlist)) continue;
      findings.push({ ruleId: rule.id, match: fullMatch, secret, start, end, entropy, line });
    }
  }
  return dedupe(findings);
}
function dedupe(findings) {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept = [];
  for (const f of sorted) {
    const clash = kept.findIndex((k) => f.start < k.end && k.start < f.end);
    if (clash === -1) {
      kept.push(f);
      continue;
    }
    const other = kept[clash];
    const fGeneric = f.ruleId === "generic-api-key";
    const oGeneric = other.ruleId === "generic-api-key";
    const preferF = oGeneric && !fGeneric || fGeneric === oGeneric && f.end - f.start > other.end - other.start;
    if (preferF) kept[clash] = f;
  }
  return kept.sort((a, b) => a.start - b.start);
}

// src/redact.ts
function redactText(text, vault, source, cfg = {}) {
  const findings = scan(text, cfg);
  if (findings.length === 0) return { text, findings, replaced: [] };
  let out = text;
  const replaced = [];
  for (const f of [...findings].sort((a, b) => b.start - a.start)) {
    const placeholder = vault.recordSecret(f.secret, f.ruleId, source);
    out = out.slice(0, f.start) + placeholder + out.slice(f.end);
    replaced.push({ placeholder, ruleId: f.ruleId });
  }
  replaced.reverse();
  return { text: out, findings, replaced };
}
function restorePlaceholders(text, vault) {
  let restored = 0;
  const out = text.replace(PLACEHOLDER_RE, (placeholder) => {
    const secret = vault.secretFor(placeholder);
    if (secret === void 0) return placeholder;
    restored++;
    return secret;
  });
  return { text: out, restored };
}

// src/version.ts
var VERSION = "1.0.1";

// src/adapters/opencode-plugin.ts
var ALLOW_TAG = "[allow-secret]";
var SECRETGATE_PLUGIN_VERSION = VERSION;
function mutateStringsInPlace(container, fn) {
  if (container === null || typeof container !== "object") return false;
  let changed = false;
  for (const key of Object.keys(container)) {
    const v = container[key];
    if (typeof v === "string") {
      const mapped = fn(v);
      if (mapped !== v) {
        container[key] = mapped;
        changed = true;
      }
    } else if (v !== null && typeof v === "object") {
      if (mutateStringsInPlace(v, fn)) changed = true;
    }
  }
  return changed;
}
var RESTORE_TOOLS = /* @__PURE__ */ new Set(["write", "edit", "patch", "multiedit"]);
var READ_TOOLS = /* @__PURE__ */ new Set(["read", "grep"]);
var SecretgatePlugin = async (_ctx) => {
  return {
    "chat.message": async (_input, output) => {
      const parts = output?.parts;
      if (!Array.isArray(parts)) return;
      if (parts.some((p) => typeof p?.text === "string" && p.text.includes(ALLOW_TAG))) return;
      const cfg = loadConfig();
      const vault = new Vault();
      for (const part of parts) {
        if (typeof part?.text !== "string") continue;
        const r = redactText(part.text, vault, "opencode:prompt", { allowlist: cfg.allowlist });
        if (r.replaced.length > 0) part.text = r.text;
      }
    },
    "tool.execute.before": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      const args = output?.args ?? {};
      if (READ_TOOLS.has(tool)) {
        const target = typeof args.filePath === "string" ? args.filePath : typeof args.path === "string" ? args.path : void 0;
        const hit = target ? sensitivePathMatch(target) : void 0;
        if (hit) {
          throw new Error(
            `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. Allow it with \`secretgate allow --path '${target}'\` if this is intentional.`
          );
        }
      }
      if (tool === "bash" && typeof args.command === "string") {
        const touched = commandTouchesSensitivePath(args.command);
        if (touched) {
          throw new Error(`secretgate: this command touches '${touched}', which looks sensitive; its content must not enter the model.`);
        }
      }
      const cfg = loadConfig();
      const restoreThis = RESTORE_TOOLS.has(tool) || tool === "bash" && cfg.restoreBash;
      if (restoreThis) {
        const vault = new Vault();
        mutateStringsInPlace(args, (s) => restorePlaceholders(s, vault).text);
      }
    },
    "tool.execute.after": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      const cfg = loadConfig();
      const vault = new Vault();
      const redact = (s) => redactText(s, vault, `opencode:${tool}`, { allowlist: cfg.allowlist }).text;
      if (typeof output?.output === "string") {
        const mapped = redact(output.output);
        if (mapped !== output.output) output.output = mapped;
      }
      if (typeof output?.title === "string") {
        const mapped = redact(output.title);
        if (mapped !== output.title) output.title = mapped;
      }
      if (output?.metadata !== null && typeof output?.metadata === "object") {
        mutateStringsInPlace(output.metadata, redact);
      }
    }
  };
};
export {
  SECRETGATE_PLUGIN_VERSION,
  SecretgatePlugin
};
