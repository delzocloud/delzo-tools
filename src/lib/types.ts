/** 'error' = we could not check (DNS timeout etc.), not the same as a bad config. */
export type AuthStatus = 'pass' | 'warning' | 'fail' | 'error';

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
}

export interface DkimResult {
  status: AuthStatus;
  record: string | null;
  selector: string;
  keys: DkimKey[];
  checkedSelectors: string[];
  details: string;
  recommendation: string;
}
