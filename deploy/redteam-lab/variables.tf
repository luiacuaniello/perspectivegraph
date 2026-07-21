# Red-team calibration lab - randomization knobs (scaffold).
#
# These variables parameterize the (uncommitted) main.tf that stands up one labelled
# environment per apply. They are the axes the engine deliberately does NOT evaluate,
# so a lab that sets them will naturally produce paths the engine surfaces but reality
# refutes - the calibration signal. See README.md. This file declares intent; it
# provisions nothing on its own.

variable "seed" {
  description = "Randomization seed; a fresh seed yields a different labelled environment."
  type        = number
}

variable "imds_posture" {
  description = "EC2 instance metadata posture: v1-optional (blind SSRF mints creds, p~0.9) or v2-required (p~0.6)."
  type        = string
  default     = "v1-optional"
  validation {
    condition     = contains(["v1-optional", "v2-required"], var.imds_posture)
    error_message = "imds_posture must be v1-optional or v2-required."
  }
}

variable "scp" {
  description = "Service Control Policy on the OU: none, deny-iam-star, or deny-outside-region. The engine cannot see SCPs, so a denying one refutes escalation paths."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "deny-iam-star", "deny-outside-region"], var.scp)
    error_message = "scp must be none, deny-iam-star, or deny-outside-region."
  }
}

variable "permission_boundary" {
  description = "Permission boundary on the escalation principal: none or read-only (caps an otherwise-admin escalation the engine over-reports)."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "read-only"], var.permission_boundary)
    error_message = "permission_boundary must be none or read-only."
  }
}

variable "condition_key" {
  description = "Condition attached to the escalation Allow: none, source-ip, or mfa. The engine treats an Allow as unconditional, so a binding condition refutes the path."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "source-ip", "mfa"], var.condition_key)
    error_message = "condition_key must be none, source-ip, or mfa."
  }
}

variable "resource_scope" {
  description = "Resource scope of the privesc grant: star (account-wide, full-probability edge) or single-resource (the resource_scoped lower-probability edge)."
  type        = string
  default     = "star"
  validation {
    condition     = contains(["star", "single-resource"], var.resource_scope)
    error_message = "resource_scope must be star or single-resource."
  }
}

variable "subnet_placement" {
  description = "Where the internet-facing instance sits: public (igw route) or private (nat route). Private must not be reachable, exercising reachability precision."
  type        = string
  default     = "public"
  validation {
    condition     = contains(["public", "private"], var.subnet_placement)
    error_message = "subnet_placement must be public or private."
  }
}

variable "privesc_primitive" {
  description = "Whether the instance role carries a real Rhino privesc primitive (true) or is a benign control (false)."
  type        = bool
  default     = true
}
