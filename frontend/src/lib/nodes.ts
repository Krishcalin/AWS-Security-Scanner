import {
  Globe, ShieldAlert, Scale, Server, IdCard, KeyRound, UserRound,
  Database, Table2, Container, Boxes, Bug, Radar, Circle, type LucideIcon,
} from 'lucide-react'

export interface NodeMeta { icon: LucideIcon; label: string; tone: string }

const META: Record<string, NodeMeta> = {
  InternetSource: { icon: Globe, label: 'Internet', tone: 'var(--ink2)' },
  AdminCapability: { icon: ShieldAlert, label: 'Admin capability', tone: 'var(--crit)' },
  LoadBalancer: { icon: Scale, label: 'Load balancer', tone: 'var(--info)' },
  EC2Instance: { icon: Server, label: 'EC2 instance', tone: 'var(--info)' },
  InstanceProfile: { icon: IdCard, label: 'Instance profile', tone: 'var(--ink2)' },
  IAMRole: { icon: KeyRound, label: 'IAM role', tone: 'var(--accent)' },
  IAMUser: { icon: UserRound, label: 'IAM user', tone: 'var(--accent)' },
  RDSInstance: { icon: Database, label: 'RDS database', tone: 'var(--gold)' },
  DynamoDBTable: { icon: Table2, label: 'DynamoDB table', tone: 'var(--gold)' },
  ECRImage: { icon: Container, label: 'Container image', tone: 'var(--info)' },
  ECSTaskDefinition: { icon: Boxes, label: 'ECS task', tone: 'var(--info)' },
  Vulnerability: { icon: Bug, label: 'CVE', tone: 'var(--crit)' },
  ThreatFinding: { icon: Radar, label: 'Threat', tone: 'var(--high)' },
}

export const nodeMeta = (kind: string): NodeMeta =>
  META[kind] ?? { icon: Circle, label: kind || 'Resource', tone: 'var(--ink3)' }

/** Short, human label for a node id (ARN tail / internet / admin / CVE). */
export function shortLabel(nid: string): string {
  if (nid === 'internet') return 'Internet'
  if (nid.startsWith('capability:admin')) return 'Admin'
  if (nid.startsWith('CVE-')) return nid
  const tail = nid.split(/[:/]/).filter(Boolean).pop() ?? nid
  return tail.length > 26 ? tail.slice(0, 25) + '…' : tail
}

/** Infer the node kind from its id — attack-path nodes carry ids, not kinds. */
export function nodeKindOf(nid: string): string {
  if (nid === 'internet') return 'InternetSource'
  if (nid.startsWith('capability:admin')) return 'AdminCapability'
  if (nid.startsWith('CVE-')) return 'Vulnerability'
  if (nid.startsWith('threat:')) return 'ThreatFinding'
  if (nid.startsWith('lb/') || nid.includes('loadbalancer')) return 'LoadBalancer'
  if (nid.includes('.dkr.ecr.') || nid.includes('@sha256:')) return 'ECRImage'
  if (nid.includes(':task-definition/') || nid.includes(':task/')) return 'ECSTaskDefinition'
  if (nid.includes(':instance-profile/')) return 'InstanceProfile'
  if (nid.includes(':instance/')) return 'EC2Instance'
  if (nid.includes(':role/')) return 'IAMRole'
  if (nid.includes(':user/')) return 'IAMUser'
  if (nid.includes(':db:') || nid.includes(':rds:')) return 'RDSInstance'
  if (nid.includes(':table/')) return 'DynamoDBTable'
  return 'Resource'
}

const REL: Record<string, string> = {
  EXPOSED_TO: 'exposed to', TARGETS: 'targets', HAS_INSTANCE_PROFILE: 'has profile',
  HAS_ROLE: 'assumes role', HAS_VULN: 'has CVE', CAN_READ_DATA: 'can read',
  CAN_PRIVESC_TO: 'can escalate', CAN_ASSUME: 'can assume', RUNS_IMAGE: 'runs',
  THREAT_ON: 'threat on', ATTACHED_TO: 'attached to',
}
export const prettyRel = (rel: string): string => REL[rel] ?? rel.toLowerCase().replace(/_/g, ' ')
