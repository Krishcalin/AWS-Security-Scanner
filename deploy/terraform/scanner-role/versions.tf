terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # >= 5.33.0: the version that introduced aws_eks_access_entry /
      # aws_eks_access_policy_association (used by the enable_eks_kspm path).
      version = ">= 5.33.0"
    }
  }
}

# AIR-GAP: `terraform init` normally fetches the aws provider from the registry. On a
# sealed host, pre-seed a provider mirror on a connected host and point init at it:
#   terraform providers mirror ./tf-provider-mirror
#   terraform init -plugin-dir=./tf-provider-mirror
