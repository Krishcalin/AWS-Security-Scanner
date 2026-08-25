import {
  Globe, ShieldAlert, Scale, Server, IdCard, KeyRound, UserRound,
  Database, Table2, Container, Boxes, Bug, Radar, Circle,
  Archive, Zap, Lock, FileKey, KeySquare, ShieldCheck, ShieldX, Hexagon,
  BadgeCheck, UserCheck, Users, Package, Box, Cloud, Unlink, Network,
  Waypoints, Cog, Building2, BrainCircuit, Bot, Notebook,
  Siren, HardDrive, FolderTree, Fingerprint, Waves, MemoryStick, Search,
  Layers, Warehouse, Clock,
  type LucideIcon,
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
  CdrDetection: { icon: Siren, label: 'Runtime detection', tone: 'var(--high)' },

  // Data terminals. S3Bucket had NO entry, so the node the flagship attack path
  // ends at was drawn as a grey circle labelled with its own class name. The rest of
  // this family arrives via _dspm_emit rather than a literal add_node, which is why
  // they were missed for as long as they were -- every one of them is a crown-jewel
  // terminal, i.e. exactly the node a reader is looking for.
  S3Bucket: { icon: Archive, label: 'S3 bucket', tone: 'var(--gold)' },
  RDSCluster: { icon: Layers, label: 'RDS cluster', tone: 'var(--gold)' },
  RedshiftCluster: { icon: Warehouse, label: 'Redshift cluster', tone: 'var(--gold)' },
  OpenSearchDomain: { icon: Search, label: 'OpenSearch domain', tone: 'var(--gold)' },
  EFSFileSystem: { icon: FolderTree, label: 'EFS file system', tone: 'var(--gold)' },
  FSxFileSystem: { icon: HardDrive, label: 'FSx file system', tone: 'var(--gold)' },
  MemoryDBCluster: { icon: MemoryStick, label: 'MemoryDB cluster', tone: 'var(--gold)' },
  KinesisStream: { icon: Waves, label: 'Kinesis stream', tone: 'var(--gold)' },
  TimestreamTable: { icon: Clock, label: 'Timestream table', tone: 'var(--gold)' },
  Secret: { icon: FileKey, label: 'Discovered secret', tone: 'var(--gold)' },
  SecretsManagerSecret: { icon: KeySquare, label: 'Secrets Manager secret', tone: 'var(--gold)' },
  KMSKey: { icon: Lock, label: 'KMS key', tone: 'var(--accent)' },

  // Compute and edge
  LambdaFunction: { icon: Zap, label: 'Lambda function', tone: 'var(--info)' },
  ECSFargateTask: { icon: Box, label: 'Fargate task', tone: 'var(--info)' },
  ECRRepository: { icon: Package, label: 'Image repository', tone: 'var(--info)' },
  ApiGateway: { icon: Network, label: 'API Gateway', tone: 'var(--info)' },
  CloudFrontDistribution: { icon: Cloud, label: 'CloudFront', tone: 'var(--info)' },
  NetworkInterface: { icon: Waypoints, label: 'Network interface', tone: 'var(--ink2)' },
  SecurityGroup: { icon: ShieldCheck, label: 'Security group', tone: 'var(--ink2)' },
  ObservedCidr: { icon: Globe, label: 'Observed CIDR', tone: 'var(--ink2)' },
  DanglingDNSRecord: { icon: Unlink, label: 'Dangling DNS', tone: 'var(--high)' },

  // Identity
  AWSAccount: { icon: Building2, label: 'AWS account', tone: 'var(--ink2)' },
  AnyPrincipal: { icon: Users, label: 'Any principal', tone: 'var(--crit)' },
  FederatedPrincipal: { icon: UserCheck, label: 'Federated principal', tone: 'var(--accent)' },
  IAMPrincipal: { icon: Fingerprint, label: 'IAM principal', tone: 'var(--accent)' },
  ServicePrincipal: { icon: Cog, label: 'Service principal', tone: 'var(--ink2)' },

  // Kubernetes
  KubePod: { icon: Hexagon, label: 'Pod', tone: 'var(--info)' },
  KubeServiceAccount: { icon: BadgeCheck, label: 'K8s service account', tone: 'var(--accent)' },
  KubeAdminCapability: { icon: ShieldX, label: 'K8s admin capability', tone: 'var(--crit)' },

  // AI. Deliberately distinct icons rather than one shared brain: a notebook, a
  // managed domain and an agent fail in different ways and get remediated
  // differently, and a graph that draws them identically hides that.
  SageMakerNotebook: { icon: Notebook, label: 'SageMaker notebook', tone: 'var(--info)' },
  SageMakerDomain: { icon: BrainCircuit, label: 'SageMaker Studio domain', tone: 'var(--gold)' },
  BedrockAgent: { icon: Bot, label: 'Bedrock agent', tone: 'var(--info)' },
  AIResource: { icon: BrainCircuit, label: 'AI resource', tone: 'var(--info)' },
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
