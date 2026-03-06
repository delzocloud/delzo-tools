export type AuthStatus = 'pass' | 'warning' | 'fail';

export interface SpfResult {
  status: AuthStatus;
  record: string | null;
  details: string;
  recommendation: string;
}

export interface DmarcResult {
  status: AuthStatus;
  record: string | null;
  policy: string | null;
  details: string;
  recommendation: string;
}

export interface DkimResult {
  status: AuthStatus;
  record: string | null;
  selector: string;
  details: string;
  recommendation: string;
}
