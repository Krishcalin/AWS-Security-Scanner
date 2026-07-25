output "role_arn" {
  description = "Paste this into the CNAPP hub tenant registry (mirrors the CFN RoleArn output)."
  value       = aws_iam_role.scanner.arn
}

output "role_name" {
  description = "The fixed role name (predictable per-account ARN)."
  value       = aws_iam_role.scanner.name
}
