export type Role = 'ADMIN' | 'ANALYST' | 'DECISION_MAKER';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export type Exposure = 'PUBLIC' | 'INTERNAL' | 'RESTRICTED';
export type Sensitivity = 'LOW' | 'MEDIUM' | 'HIGH';
export type CorrectionStatus =
  | 'IMPORTED' | 'VALIDATED' | 'PRIORITIZED' | 'ASSIGNED' | 'IN_REMEDIATION'
  | 'REMEDIATED' | 'VERIFIED' | 'CLOSED' | 'REJECTED';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  mustChangePassword: boolean;
  active?: boolean;
  createdAt?: string;
}

export interface Application {
  id: string;
  name: string;
  description: string | null;
  exposure: Exposure;
  sensitivity: Sensitivity;
  findingsCount?: number;
  scansCount?: number;
}

export interface Page<T> {
  total: number;
  page: number;
  pageSize: number;
  items: T[];
}

export interface FindingRow {
  id: string;
  title: string;
  severity: number;
  cweId: number | null;
  cveId: string | null;
  instancesCount: number;
  lastSeenAt: string;
  priority: Priority | null;
  modelPriority: Priority | null;
  expertPriority: Priority | null;
  modelProbability: number | null;
  exploitProbability: number | null;
  application: { id: string; name: string };
  correction: { status: CorrectionStatus; assigneeId: string | null; dueDate: string | null } | null;
}

export interface Contribution { feature: string; contribution: number }

export interface Prediction {
  id: string;
  model: 'M1' | 'M2';
  version: string;
  simulated: boolean;
  provider: string;
  probability: number;
  priority: Priority | null;
  explanation: Contribution[] | null;
  createdAt: string;
}

export interface FindingDetail extends Omit<FindingRow, 'correction' | 'application'> {
  description: string;
  solution: string | null;
  confidence: string | null;
  sampleUrls: string[] | null;
  firstSeenAt: string;
  application: { id: string; name: string; exposure: Exposure; sensitivity: Sensitivity };
  correction: {
    status: CorrectionStatus;
    assigneeId: string | null;
    assignee: { id: string; name: string } | null;
    dueDate: string | null;
    comment: string | null;
  } | null;
  annotations: { id: string; priority: Priority; comment: string | null; createdAt: string; annotator: { name: string } }[];
  predictions: { m1: Prediction | null; m2: Prediction | null };
}

export interface Aggregate {
  simulated: boolean;
  generatedAt: string;
  totals: { findings: number; open: number };
  byPriority: Record<Priority | 'NONE', number>;
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
  byApplication: { applicationId: string; name: string; exposure: string; sensitivity: string; total: number; P1: number; P2: number; P3: number; P4: number }[];
  topFindings?: { id: string; title: string; severity: number; priority: Priority | null; modelProbability: number | null; application: { id: string; name: string }; correction: { status: CorrectionStatus } | null }[];
}

export interface ScanRow {
  id: string;
  fileName: string;
  sizeBytes: number;
  findingsTotal: number;
  findingsNew: number;
  findingsUpdated: number;
  status: string;
  importedAt: string;
  application: { id: string; name: string };
  importedBy: { id: string; name: string };
}

export interface ImportSummary {
  scanId: string;
  findingsTotal: number;
  findingsNew: number;
  findingsUpdated: number;
  byPriority: Record<Priority, number>;
  provider: string;
  simulated: boolean;
}

export interface AuditEntry {
  id: string;
  createdAt: string;
  userId: string | null;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILURE';
  ip: string | null;
  metadata: unknown;
}

export interface ModelState {
  mode: string;
  message: string;
  version: string;
  configuredProvider: string;
  activeProvider: string;
  anthropicConfigured: boolean;
  metrics: null;
  metricsPlanned: string[];
}

export const PRIORITY_LABEL: Record<Priority, string> = { P1: 'Critique', P2: 'Élevée', P3: 'Moyenne', P4: 'Faible' };
export const SEVERITY_LABEL = ['Information', 'Faible', 'Moyenne', 'Élevée'];
export const ROLE_LABEL: Record<Role, string> = { ADMIN: 'Administrateur', ANALYST: 'Analyste', DECISION_MAKER: 'Décideur' };
export const EXPOSURE_LABEL: Record<Exposure, string> = { PUBLIC: 'Publique', INTERNAL: 'Interne', RESTRICTED: 'Restreinte' };
export const SENSITIVITY_LABEL: Record<Sensitivity, string> = { LOW: 'Faible', MEDIUM: 'Moyenne', HIGH: 'Élevée' };
export const STATUS_LABEL: Record<CorrectionStatus, string> = {
  IMPORTED: 'Importé', VALIDATED: 'Validé', PRIORITIZED: 'Priorisé', ASSIGNED: 'Assigné', IN_REMEDIATION: 'En correction',
  REMEDIATED: 'Corrigé', VERIFIED: 'Vérifié', CLOSED: 'Clos', REJECTED: 'Rejeté',
};
export const FEATURE_LABEL: Record<string, string> = {
  technicalSeverity: 'Gravité technique', exposure: 'Exposition', sensitivity: 'Sensibilité des données',
  m1Probability: "Probabilité d'exploitation (M1)", controlsInPlace: 'Contrôles en place', remediationHistory: 'Historique de correction',
};

/** Transitions autorisées (miroir de l'API ; la vraie validation reste côté serveur). */
export const TRANSITIONS: Record<CorrectionStatus, CorrectionStatus[]> = {
  IMPORTED: ['VALIDATED'],
  VALIDATED: ['PRIORITIZED', 'REJECTED'],
  PRIORITIZED: ['ASSIGNED', 'REJECTED'],
  ASSIGNED: ['IN_REMEDIATION'],
  IN_REMEDIATION: ['REMEDIATED'],
  REMEDIATED: ['VERIFIED'],
  VERIFIED: ['CLOSED', 'IN_REMEDIATION'],
  CLOSED: [],
  REJECTED: [],
};
