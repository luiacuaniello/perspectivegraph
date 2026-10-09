output "role_arn" {
  description = "AWS_ROLE_ARN for the backend (connectors.aws.roleArn in the chart), or the role for an EKS Pod Identity association."
  value       = aws_iam_role.readonly.arn
}
