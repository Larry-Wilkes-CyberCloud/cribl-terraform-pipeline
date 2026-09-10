# User-supplied parameters
#
# Copy terraform.tfvars.example to terraform.tfvars and fill in real values.
# Never commit terraform.tfvars — it holds live credentials (see .gitignore).
#
# NOTE ON AUTH: Cribl.Cloud/on-prem credentials are NOT set as Terraform
# variables here — the provider reads them from environment variables
# (or a ~/.cribl/credentials file) instead, per
# https://docs.cribl.io/cribl-as-code/terraform-auth/. See provider.tf
# and README.md for exactly which env vars to export before you run
# terraform, for either deployment target.

variable "on_prem" {
  type        = bool
  description = "true = target a self-hosted/Docker Cribl Stream instance (auth via CRIBL_ONPREM_* env vars). false = target Cribl.Cloud (auth via CRIBL_CLIENT_ID/CRIBL_CLIENT_SECRET/CRIBL_ORGANIZATION_ID/CRIBL_WORKSPACE_ID env vars)."
  default     = true
}

variable "worker_group_id" {
  type        = string
  description = "ID for the new Worker Group this project creates. Must not already exist in your deployment."
  default     = "cg-intake-hipaa-demo"
}

variable "worker_group_region" {
  type        = string
  description = "Cloud region for the Worker Group. Only used when on_prem = false (Cribl-managed cloud infrastructure) — ignored for on-prem."
  default     = "us-east-1"
}

variable "syslog_port" {
  type        = number
  description = "TCP port the Syslog Source listens on."
  default     = 9021
}

variable "aws_bucket_name" {
  type        = string
  description = "Name of the S3 bucket the pipeline writes minimized/masked events to."
}

variable "aws_region" {
  type        = string
  description = "AWS region of the S3 bucket, e.g. us-east-1."
}

variable "aws_api_key" {
  type        = string
  description = "AWS Access Key ID for the S3 Destination. Scope this IAM user to s3:PutObject on the target bucket only (least privilege)."
  sensitive   = true
}

variable "aws_secret_key" {
  type        = string
  description = "AWS Secret Access Key for the S3 Destination."
  sensitive   = true
}

variable "kms_key_id" {
  type        = string
  description = "Optional: ARN of a customer-managed KMS key for S3 server-side encryption. Leave blank to use SSE-S3 (AES256) instead of SSE-KMS."
  default     = ""
}

# ---------------------------------------------------------------------------
# OpenTelemetry ingest + export
# ---------------------------------------------------------------------------

variable "otel_port" {
  type        = number
  description = "Port the OpenTelemetry Source listens on for OTLP traffic."
  default     = 4317
}

variable "otel_protocol" {
  type        = string
  description = "Transport for the OpenTelemetry Source. One of: grpc, http."
  default     = "grpc"
}

variable "otel_bearer_token" {
  type        = string
  description = "Bearer token OTLP clients must present to this Source. Generate any random secret string — this isn't tied to an external identity provider."
  sensitive   = true
  default     = ""
}

variable "otel_destination_endpoint" {
  type        = string
  description = "OTLP endpoint to export extracted spans/metrics/logs to, e.g. a Grafana Cloud, Honeycomb, or self-hosted otel-collector OTLP receiver. Required for the OTel destination to do anything meaningful."
}

variable "otel_destination_protocol" {
  type        = string
  description = "Transport for the OpenTelemetry Destination. One of: grpc, http."
  default     = "grpc"
}

variable "otel_destination_header_name" {
  type        = string
  description = "Optional auth header name required by your OTLP backend (e.g. \"Authorization\" for Grafana Cloud, \"x-honeycomb-team\" for Honeycomb). Leave blank if the backend needs no auth header."
  default     = ""
}

variable "otel_destination_header_value" {
  type        = string
  description = "Value for otel_destination_header_name (e.g. \"Basic <base64 instanceID:apiKey>\" for Grafana Cloud, or a raw API key for Honeycomb)."
  sensitive   = true
  default     = ""
}
