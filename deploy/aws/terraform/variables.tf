variable "role_name" {
  description = "The role's name."
  type        = string
  default     = "PerspectiveGraphReadOnly"
}

variable "trust_eks_pod_identity" {
  description = "Trust EKS Pod Identity in this account, for a backend running on EKS here: an association hands the backend's service account (<release>-perspectivegraph-backend) this role, and no AWS_ROLE_ARN is needed."
  type        = bool
  default     = false
}

variable "trusted_principal_arns" {
  description = "Roles or users the backend runs as when it assumes this role with AWS_ROLE_ARN - from another account, a VM, a CI job."
  type        = list(string)
  default     = []
}

variable "assumable_role_arns" {
  description = "For a hub role: the read-only roles in OTHER accounts this one may assume, so one backend reads several accounts."
  type        = list(string)
  default     = []
}
