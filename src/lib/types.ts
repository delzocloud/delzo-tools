/** 'error' = we could not check (DNS timeout etc.), not the same as a bad config. */
export type AuthStatus = 'pass' | 'warning' | 'fail' | 'error' | 'unverified';

export type SpfQualifier = '+' | '-' | '~' | '?';

export interface SpfResult {
  status: AuthStatus;
  record: string | null;
  records: string[];
  allQualifier: SpfQualifier | null;
  lookups: number;
  details: string;
  recommendation: string;
}

export interface DmarcResult {
  status: AuthStatus;
  record: string | null;
  policy: string | null;
  subdomainPolicy: string | null;
  effectivePolicy: string | null;
  pct: number;
  rua: boolean;
  inheritedFrom: string | null;
  details: string;
  recommendation: string;
}

export interface DkimKey {
  selector: string;
  record: string;
  revoked: boolean;
  /** Provider guessed from the CNAME target or the selector name. */
  provider: string | null;
}

export interface DkimResult {
  status: AuthStatus;
  record: string | null;
  selector: string;
  keys: DkimKey[];
  checkedSelectors: string[];
  provider: string | null;
  /** _domainkey answers any label (wildcard): hits are not reliable. */
  wildcard: boolean;
  details: string;
  recommendation: string;
}
