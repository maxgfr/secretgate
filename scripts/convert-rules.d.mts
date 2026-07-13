// Hand-written declarations so TypeScript tests can import the dev-time
// converter script (plain ESM, not part of the bundle).
export interface ConvertedRegex {
  source: string;
  flags: string;
  loosened: string[];
}

export function convertGoRegex(goSource: string): ConvertedRegex;

export function convertConfig(): Promise<{
  rules: Array<{
    id: string;
    regex: { source: string; flags: string };
    entropy?: number;
    secretGroup?: number;
    keywords: string[];
    allowlists?: Array<{
      condition?: "AND" | "OR";
      regexTarget?: "match" | "line";
      regexes?: Array<{ source: string; flags: string }>;
      stopwords?: string[];
      paths?: Array<{ source: string; flags: string }>;
    }>;
  }>;
  dropped: string[];
  loosened: string[];
  globalAllowlist: { paths: string[]; regexes: Array<{ source: string; flags: string }>; stopwords: string[] };
}>;
