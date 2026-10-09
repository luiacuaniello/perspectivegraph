# PerspectiveGraph read-only role - what the AWS connector reads an account with: the
# AWS-managed SecurityAudit policy, plus the two EKS Pod Identity reads it does not include,
# and nothing that writes. The same role as ../readonly-role.cfn.yaml; deploy it in every
# account to be read.
#
#   module "perspectivegraph_readonly" {
#     source                 = "github.com/luiacuaniello/perspectivegraph//deploy/aws/terraform"
#     trust_eks_pod_identity = true
#   }

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  trusts_someone = var.trust_eks_pod_identity || length(var.trusted_principal_arns) > 0
}

data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = var.trust_eks_pod_identity ? [1] : []
    content {
      sid     = "EksPodIdentity"
      actions = ["sts:AssumeRole", "sts:TagSession"]
      principals {
        type        = "Service"
        identifiers = ["pods.eks.amazonaws.com"]
      }
      # Only pods in this account's clusters, not another account's association.
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.trusted_principal_arns) > 0 ? [1] : []
    content {
      sid     = "BackendPrincipal"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.trusted_principal_arns
      }
    }
  }
}

resource "aws_iam_role" "readonly" {
  name                 = var.role_name
  description          = "PerspectiveGraph - read-only access for the attack-path engine's AWS connector."
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  tags                 = { app = "perspectivegraph" }

  lifecycle {
    precondition {
      condition     = local.trusts_someone
      error_message = "Set trust_eks_pod_identity, trusted_principal_arns, or both - a role nobody can assume reads nothing."
    }
  }
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.readonly.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit"
}

# Which IAM role each EKS service account gets out as: the bridge from a pod to the
# account. SecurityAudit reads access entries but not these.
data "aws_iam_policy_document" "eks_pod_identity_read" {
  statement {
    sid = "EksPodIdentityRead"
    actions = [
      "eks:ListPodIdentityAssociations",
      "eks:DescribePodIdentityAssociation",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "eks_pod_identity_read" {
  name   = "perspectivegraph-eks-pod-identity-read"
  role   = aws_iam_role.readonly.id
  policy = data.aws_iam_policy_document.eks_pod_identity_read.json
}

data "aws_iam_policy_document" "assume_other_accounts" {
  count = length(var.assumable_role_arns) > 0 ? 1 : 0
  statement {
    sid       = "AssumeTheOtherAccountsReadOnlyRoles"
    actions   = ["sts:AssumeRole"]
    resources = var.assumable_role_arns
  }
}

resource "aws_iam_role_policy" "assume_other_accounts" {
  count  = length(var.assumable_role_arns) > 0 ? 1 : 0
  name   = "perspectivegraph-assume-readonly-roles"
  role   = aws_iam_role.readonly.id
  policy = data.aws_iam_policy_document.assume_other_accounts[0].json
}
