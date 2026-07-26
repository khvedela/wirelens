export interface SourceTreeIdentity {
  baseRevision: string;
  sha256: string;
}

export function sourceTreeIdentity(): Promise<SourceTreeIdentity>;
