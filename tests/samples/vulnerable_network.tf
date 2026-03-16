# =============================================================================
# DELIBERATELY VULNERABLE AWS NETWORK -- FOR SCANNER TESTING ONLY
# This file intentionally contains security misconfigurations across 25+
# AWS service categories. DO NOT deploy to a real AWS account.
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  # VULN: Hardcoded AWS credentials (AWS-CRED-TF-001 / AWS-CRED-TF-002)
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# =============================================================================
# VPC + NETWORKING (AWS-VPC-TF-001 / AWS-VPC-TF-002)
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  # No flow logs attached
  tags = { Name = "vulnerable-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"

  # VULN: Auto-assign public IPs (AWS-VPC-TF-002)
  map_public_ip_on_launch = true

  tags = { Name = "public-subnet-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"

  # VULN: Auto-assign public IPs (AWS-VPC-TF-002)
  map_public_ip_on_launch = true

  tags = { Name = "public-subnet-b" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"
  tags              = { Name = "private-subnet-a" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

# VULN: No VPC Flow Log resource defined (AWS-VPC-TF-001)

# =============================================================================
# SECURITY GROUPS (AWS-SG-TF-001 / AWS-SG-TF-002 / AWS-SG-TF-003)
# =============================================================================

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  # VULN: SSH open to the world (AWS-SG-TF-001)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  # VULN: RDP open to the world (AWS-SG-TF-002)
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP from anywhere"
  }

  # VULN: All ports open to the world (AWS-SG-TF-003)
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All TCP from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name   = "db-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}

# =============================================================================
# IAM (AWS-IAM-TF-001 / AWS-IAM-TF-002 / AWS-IAM-TF-003 / AWS-IAM-TF-004)
# =============================================================================

# VULN: Wildcard actions + wildcard resource (AWS-IAM-TF-001)
resource "aws_iam_policy" "admin_policy" {
  name = "admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# VULN: Wildcard principal in trust policy (AWS-IAM-TF-002)
resource "aws_iam_role" "ec2_role" {
  name = "ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_admin" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# VULN: IAM user with inline policy allowing password reset without MFA (AWS-IAM-TF-003/004)
resource "aws_iam_user" "svc_account" {
  name = "svc-account"
}

resource "aws_iam_user_policy" "svc_policy" {
  name = "svc-policy"
  user = aws_iam_user.svc_account.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:UpdateLoginProfile"]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# S3 (AWS-S3-TF-001 to 006)
# =============================================================================

# VULN: Public ACL (AWS-S3-TF-001)
resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket-prod"
  acl    = "public-read"
}

# VULN: Block Public Access disabled (AWS-S3-TF-002/003/004/005)
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "logs" {
  bucket = "company-logs-bucket"
}

resource "aws_s3_bucket" "backups" {
  bucket        = "company-backups-prod"
  force_destroy = true
}

# =============================================================================
# EC2 (AWS-EC2-TF-001 / AWS-EC2-TF-002 / AWS-EC2-TF-003)
# =============================================================================

resource "aws_instance" "web_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # VULN: IMDSv1 enabled (AWS-EC2-TF-001)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }

  # VULN: Public IP enabled (AWS-EC2-TF-002)
  associate_public_ip_address = true

  # VULN: Root volume not encrypted (AWS-EC2-TF-003 / AWS-EBS-TF-001)
  root_block_device {
    volume_size = 30
    encrypted   = false
  }

  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    export API_KEY="hardcoded-api-key-value"
    yum install -y httpd
    systemctl start httpd
  EOF

  tags = { Name = "web-server" }
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# VULN: Standalone EBS volume not encrypted (AWS-EBS-TF-001)
resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
  tags              = { Name = "data-volume" }
}

# =============================================================================
# RDS (AWS-RDS-TF-001 to 006)
# =============================================================================

resource "aws_db_subnet_group" "main" {
  name       = "main-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.public_a.id]
}

resource "aws_db_instance" "postgres" {
  identifier             = "prod-postgres"
  engine                 = "postgres"
  engine_version         = "14.8"
  instance_class         = "db.t3.medium"
  allocated_storage      = 100
  db_name                = "appdb"
  username               = "admin"
  password               = "Password123!"
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  # VULN: Publicly accessible (AWS-RDS-TF-001)
  publicly_accessible = true

  # VULN: Storage not encrypted (AWS-RDS-TF-002)
  storage_encrypted = false

  # VULN: Backup retention disabled (AWS-RDS-TF-003)
  backup_retention_period = 0

  # VULN: Deletion protection off (AWS-RDS-TF-004)
  deletion_protection = false

  # VULN: No enhanced monitoring (AWS-RDS-TF-005)
  monitoring_interval = 0

  # VULN: Multi-AZ disabled (AWS-RDS-TF-006)
  multi_az = false

  skip_final_snapshot = true
}

# =============================================================================
# CLOUDTRAIL (AWS-CT-TF-001 / AWS-CT-TF-002 / AWS-CT-TF-003)
# =============================================================================

resource "aws_cloudtrail" "main" {
  name           = "main-trail"
  s3_bucket_name = aws_s3_bucket.logs.id

  # VULN: Log file validation disabled (AWS-CT-TF-001)
  enable_log_file_validation = false

  # VULN: Single-region trail (AWS-CT-TF-002)
  is_multi_region_trail = false

  # VULN: Global service events excluded (AWS-CT-TF-003)
  include_global_service_events = false
}

# =============================================================================
# KMS (AWS-KMS-TF-001)
# =============================================================================

resource "aws_kms_key" "app_key" {
  description = "Application encryption key"

  # VULN: Key rotation disabled (AWS-KMS-TF-001)
  enable_key_rotation = false
}

# =============================================================================
# CLOUDFRONT (AWS-CF-TF-001 / AWS-CF-TF-002)
# =============================================================================

resource "aws_cloudfront_distribution" "web" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.data.bucket_domain_name
    origin_id   = "s3-data"

    s3_origin_config {
      origin_access_identity = ""
    }
  }

  # VULN: Allows HTTP (not HTTPS-only) (AWS-CF-TF-001)
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-data"
    viewer_protocol_policy = "allow-all"

    # VULN: Minimum TLS version too low (AWS-CF-TF-002)
    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"
  }
}

# =============================================================================
# ELASTICACHE (AWS-ECACHE-TF-001 / AWS-ECACHE-TF-002)
# =============================================================================

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "prod-redis"
  description          = "Production Redis cluster"
  node_type            = "cache.t3.medium"
  num_cache_clusters   = 2
  port                 = 6379

  # VULN: Encryption at rest disabled (AWS-ECACHE-TF-001)
  at_rest_encryption_enabled = false

  # VULN: Encryption in transit disabled (AWS-ECACHE-TF-002)
  transit_encryption_enabled = false
}

# =============================================================================
# ECS (AWS-ECS-TF-001 / AWS-ECS-TF-002)
# =============================================================================

resource "aws_ecs_task_definition" "app" {
  family                   = "app-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  container_definitions = jsonencode([
    {
      name  = "app"
      image = "nginx:latest"
      portMappings = [{ containerPort = 80, hostPort = 80 }]

      # VULN: Privileged mode enabled (AWS-ECS-TF-001)
      privileged = true

      # VULN: Writable root filesystem (AWS-ECS-TF-002)
      readonlyRootFilesystem = false

      environment = [
        { name = "DB_PASSWORD", value = "prod-db-password-123" },
        { name = "SECRET_KEY", value = "my-secret-key-value" }
      ]
    }
  ])
}

# =============================================================================
# OPENSEARCH (AWS-OS-TF-001 / AWS-OS-TF-002)
# =============================================================================

resource "aws_opensearch_domain" "search" {
  domain_name    = "prod-search"
  engine_version = "OpenSearch_2.3"

  cluster_config {
    instance_type = "t3.small.search"
  }

  # VULN: HTTPS not enforced (AWS-OS-TF-001)
  domain_endpoint_options {
    enforce_https = false
  }

  # VULN: Node-to-node encryption disabled (AWS-OS-TF-002)
  node_to_node_encryption {
    enabled = false
  }

  encrypt_at_rest {
    enabled = false
  }
}

# =============================================================================
# REDSHIFT (AWS-RS-TF-001 / AWS-RS-TF-002)
# =============================================================================

resource "aws_redshift_cluster" "dw" {
  cluster_identifier = "prod-redshift"
  database_name      = "analytics"
  master_username    = "admin"
  master_password    = "Redshift123!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  # VULN: Publicly accessible (AWS-RS-TF-001)
  publicly_accessible = true

  # VULN: Encryption disabled (AWS-RS-TF-002)
  encrypted = false
}

# =============================================================================
# ECR (AWS-ECR-TF-001)
# =============================================================================

resource "aws_ecr_repository" "app" {
  name = "app-images"

  # VULN: Mutable image tags (AWS-ECR-TF-001)
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

# =============================================================================
# DYNAMODB (AWS-DDB-TF-001)
# =============================================================================

resource "aws_dynamodb_table" "sessions" {
  name         = "user-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  # VULN: SSE not enabled (AWS-DDB-TF-001)
  server_side_encryption {
    enabled = false
  }

  point_in_time_recovery {
    enabled = false
  }
}

# =============================================================================
# LAMBDA (AWS-LAM-TF-001)
# =============================================================================

resource "aws_lambda_function" "api_handler" {
  filename      = "lambda.zip"
  function_name = "api-handler"
  role          = aws_iam_role.ec2_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"

  # VULN: No reserved concurrency (throttling protection absent) (AWS-LAM-TF-001)
  # reserved_concurrent_executions not set

  environment {
    variables = {
      DB_HOST     = aws_db_instance.postgres.endpoint
      DB_PASSWORD = "lambda-db-password"
      API_SECRET  = "AKIA5EXAMPLE000SECRET"
    }
  }
}

# =============================================================================
# API GATEWAY (AWS-APIGW-TF-001)
# =============================================================================

resource "aws_api_gateway_rest_api" "app_api" {
  name = "app-api"
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.app_api.id
  stage_name    = "prod"
  deployment_id = "placeholder"

  # VULN: Access logging not configured (AWS-APIGW-TF-001)
  # access_log_settings block absent
}

# =============================================================================
# CLOUDWATCH (AWS-CW-TF-001 / AWS-CW-TF-002 / AWS-CW-TF-003)
# =============================================================================

# VULN: Log group with no retention policy (AWS-CW-TF-001)
resource "aws_cloudwatch_log_group" "app_logs" {
  name = "/app/production"
  # retention_in_days not set → logs kept forever
  # kms_key_id not set → unencrypted (AWS-CW-TF-002)
}

# VULN: CloudWatch alarm with no actions (AWS-CW-TF-003)
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization is too high"
  # alarm_actions not set (AWS-CW-TF-003)
}

# =============================================================================
# WAF (AWS-WAF-TF-001)
# =============================================================================

resource "aws_wafv2_web_acl" "main" {
  name  = "main-waf"
  scope = "CLOUDFRONT"

  # VULN: Default action is ALLOW (AWS-WAF-TF-001)
  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "main-waf"
    sampled_requests_enabled   = false
  }
}

# =============================================================================
# GUARDDUTY (AWS-GD-TF-001)
# =============================================================================

# VULN: GuardDuty detector disabled (AWS-GD-TF-001)
resource "aws_guardduty_detector" "main" {
  enable = false
}

# =============================================================================
# CONFIG (AWS-CFG-TF-001 / AWS-CFG-TF-002)
# =============================================================================

resource "aws_config_configuration_recorder" "main" {
  name     = "main-recorder"
  role_arn = aws_iam_role.ec2_role.arn

  recording_group {
    # VULN: Not recording all resource types (AWS-CFG-TF-001)
    all_supported = false

    # VULN: Global resources not included (AWS-CFG-TF-002)
    include_global_resource_types = false
  }
}

# =============================================================================
# ELASTIC BEANSTALK (AWS-EB-TF-001 / AWS-EB-TF-002)
# =============================================================================

resource "aws_elastic_beanstalk_environment" "app" {
  name                = "app-prod"
  application         = "my-app"
  solution_stack_name = "64bit Amazon Linux 2 v3.5.0 running Python 3.8"

  # VULN: HTTPS listener not configured (AWS-EB-TF-001)
  setting {
    namespace = "aws:elb:listener:80"
    name      = "ListenerProtocol"
    value     = "HTTP"
  }

  # VULN: Managed platform updates disabled (AWS-EB-TF-002)
  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "ManagedActionsEnabled"
    value     = "false"
  }
}

# =============================================================================
# SAGEMAKER (AWS-SM-TF-001 / AWS-SM-TF-002)
# =============================================================================

resource "aws_sagemaker_notebook_instance" "ml_notebook" {
  name          = "ml-notebook"
  role_arn      = aws_iam_role.ec2_role.arn
  instance_type = "ml.t3.medium"

  # VULN: Direct internet access enabled (AWS-SM-TF-001)
  direct_internet_access = "Enabled"

  # VULN: No KMS encryption for storage (AWS-SM-TF-002)
  # kms_key_id not set
}

# =============================================================================
# BEDROCK (AWS-BR-TF-001)
# =============================================================================

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = true
    text_data_delivery_enabled      = true

    s3_config {
      bucket_name = aws_s3_bucket.logs.id
      key_prefix  = "bedrock/"
    }
  }
}

# VULN: Bedrock Agent with no guardrails (AWS-BR-TF-001)
resource "aws_bedrockagent_agent" "assistant" {
  agent_name            = "prod-assistant"
  agent_resource_role_arn = aws_iam_role.ec2_role.arn
  foundation_model      = "anthropic.claude-3-sonnet-20240229-v1:0"
  description           = "Production AI assistant"

  # guardrail_configuration block absent — no guardrails
  idle_session_ttl_in_seconds = 7200
}

# =============================================================================
# STEP FUNCTIONS (AWS-SFN-TF-001 / AWS-SFN-TF-002)
# =============================================================================

resource "aws_sfn_state_machine" "pipeline" {
  name     = "data-pipeline"
  role_arn = aws_iam_role.ec2_role.arn

  definition = jsonencode({
    Comment = "Data processing pipeline"
    StartAt = "ProcessData"
    States = {
      ProcessData = {
        Type     = "Task"
        Resource = aws_lambda_function.api_handler.arn
        End      = true
      }
    }
  })

  # VULN: Logging disabled (AWS-SFN-TF-001)
  # logging_configuration block absent

  # VULN: X-Ray tracing disabled (AWS-SFN-TF-002)
  tracing_configuration {
    enabled = false
  }
}

# =============================================================================
# SNS (for completeness)
# =============================================================================

resource "aws_sns_topic" "alerts" {
  name = "prod-alerts"
  # No KMS encryption
}

# =============================================================================
# SQS
# =============================================================================

resource "aws_sqs_queue" "jobs" {
  name = "job-queue"
  # No KMS encryption, no DLQ
  visibility_timeout_seconds = 30
  message_retention_seconds  = 86400
}

# =============================================================================
# OUTPUTS (exposing sensitive values — intentional vuln)
# =============================================================================

output "db_password" {
  value     = aws_db_instance.postgres.password
  sensitive = false
}

output "rds_endpoint" {
  value = aws_db_instance.postgres.endpoint
}
