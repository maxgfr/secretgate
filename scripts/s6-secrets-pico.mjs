// Dev-only adapter for scripts/model-compare.mjs: everything specific to
// s6-secrets-pico (skycmd, Apache-2.0) behind one small interface. The model
// reads a short text and answers four typed questions; this file says which
// file it is, which questions it is asked, and how a long text is cut for it.
// The engine host (scripts/sky-wasm.mjs) knows none of this.
//
// Adapter contract, shared by any later model: `ASSET` (pinned file),
// `units(text)` (the pieces of text the model reads, each with its first line)
// and `score(engine, unit)` (P(a real secret) for one piece). A model that
// scores one rule candidate in its context would export the same three, with
// `units` built from the scanner's findings instead of from line windows.

// Pinned by commit AND by content (Hugging Face model repository, not `main`).
export const ASSET = {
  file: "s6-secrets-pico.gguf",
  url: "https://huggingface.co/maxgfr/s6-secrets-pico/resolve/170428032aad2de3047e37429bec465f4b221858/s6-secrets-pico.gguf",
  sha256: "1fa48c1530607d6a81ee64ad858aebfe4a49f9e5e88b1ac89eb63f2cc73a097a",
  bytes: 250_272,
};

// The questions the model was trained on, word for word (skycmd `sky-data
// secret-jev`, crates/sky-data/src/secrets.rs). It knows no other phrasing.
export const SECRET_QUESTION = {
  t: "noul",
  ins: "Does the text expose a usable secret (an API key, token, password or private key) that should be revoked?",
  opts: ["false: no, the statement does not hold", "true: yes, the statement holds"],
};
export const SERVICE_QUESTION = {
  t: "choice",
  ins: "Which service issued the key or token in the text?",
  opts: [
    "aws",
    "github",
    "gitlab",
    "stripe",
    "slack",
    "openai",
    "anthropic",
    "google",
    "huggingface",
    "sendgrid",
    "npm",
    "private_key: a PEM private key",
    "database: a connection string with its password",
    "generic: a key or token of another service",
    "none: no actual key or token",
  ],
};
export const KIND_QUESTION = {
  t: "choice",
  ins: "What kind of value is assigned or sent in the text?",
  opts: [
    "secret: a live, usable credential",
    "test: a test or sandbox credential",
    "public: a publishable key meant to be public",
    "placeholder: a placeholder, an example, a redacted value or a reference",
    "other: not a credential, even if it looks random",
  ],
};

/** P(the text exposes a usable secret): one decision. */
export const score = (engine, state) => engine.decide(SECRET_QUESTION.t, SECRET_QUESTION.ins, SECRET_QUESTION.opts, state).probs[1];

// How text is cut for the model. Its training texts have 2 to 7 lines (111
// characters at the median of its bench, 283 at most) and its state window
// holds 320 tokens; the engine drops every token past the window without a
// word (crates/sky-infer/src/s2/prompt.rs, `build_state`), so a whole file
// handed over in one piece is judged on its first few hundred characters. Chunks
// follow the training shape: whole lines, at most 7 of them and at most 300
// characters (code tokenises to about two characters per token, a random key
// to about one, so 300 characters stay inside the window). A longer line is cut
// into 300-character pieces that overlap by 100, so any key up to 100
// characters long lies whole inside one piece.
export const CHUNK_MAX_LINES = 7;
export const CHUNK_MAX_CHARS = 300;

export function units(text, maxLines = CHUNK_MAX_LINES, maxChars = CHUNK_MAX_CHARS) {
  const chunks = [];
  let buf = [];
  let start = 0;
  let size = 0;
  const flush = () => {
    if (buf.some((l) => l.trim().length > 0)) chunks.push({ text: buf.join("\n"), line: start, lines: buf.length });
    buf = [];
    size = 0;
  };
  const step = Math.max(1, Math.min(200, maxChars - 100));
  text.split("\n").forEach((raw, i) => {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.length > maxChars) {
      flush();
      for (let at = 0; ; at += step) {
        const piece = line.slice(at, at + maxChars);
        if (piece.trim().length > 0) chunks.push({ text: piece, line: i, lines: 1 });
        if (at + maxChars >= line.length) break;
      }
      return;
    }
    if (buf.length > 0 && (buf.length >= maxLines || size + 1 + line.length > maxChars)) flush();
    if (buf.length === 0) start = i;
    size += (buf.length > 0 ? 1 : 0) + line.length;
    buf.push(line);
  });
  flush();
  return chunks;
}
