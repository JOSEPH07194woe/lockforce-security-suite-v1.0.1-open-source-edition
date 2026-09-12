
// Shared TypeScript types
export type Severity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';

// Metadata describing an implemented LockForce feature (presentation only).
export type FeatureDef = {
  id: string;
  name: string;
  description: string;
  category: string;
  cwsCompliant: boolean;
};

export interface SecurityEvent {
  id: string;
  time: number;
  severity: Severity;
  category: string;
  title: string;
  source: string;
  reasons: string[];
  action: string;
}

export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  reasons: string[];
  score: number;
}

export interface Settings {
  shields: Record<string, boolean>;
  mode: 'beginner' | 'balanced' | 'advanced' | 'ultra';
  lockdown: boolean;
  autofillEnabled: boolean;
  notificationsEnabled: boolean;
}
