// Structural copy of deepsec plugin contracts — swap to "deepsec/config" import when published
export interface MatcherPlugin {
  slug: string;
  description: string;
  noiseTier: "precise" | "normal" | "noisy";
  filePatterns: string[];
  examples?: string[];
  match(content: string, filePath: string): Array<{ vulnSlug: string; lineNumbers: number[]; snippet: string; matchedPattern: string }>;
}

export interface FindingNotification {
  notifierName: string;
  notifiedAt: string;
  externalId?: string;
  externalUrl?: string;
  extra?: Record<string, unknown>;
}

export interface NotifierPlugin {
  name: string;
  notify(params: { finding: unknown; record: { filePath: string }; projectId: string }): Promise<FindingNotification>;
}

export interface DeepsecPlugin {
  name: string;
  matchers?: MatcherPlugin[];
  notifiers?: NotifierPlugin[];
}
