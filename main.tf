# cribl-terraform-pipeline
#
# Provisions a Cribl Stream Worker Group, Syslog Source, a two-stage
# data-minimization Pipeline, an S3 Destination, and the Route tying
# them together — entirely via Terraform.
#
# See README.md for the HIPAA / NIST 800-53 control mapping this
# pipeline is designed against.

locals {
  # SSE-KMS if a customer-managed key is supplied, otherwise SSE-S3.
  s3_server_side_encryption = var.kms_key_id != "" ? "aws:kms" : "AES256"

  # Only attach an auth header to the OTel export if one was supplied —
  # not every OTLP backend needs one (e.g. an unauthenticated local collector).
  otel_destination_metadata = var.otel_destination_header_name != "" ? [
    {
      name  = var.otel_destination_header_name
      value = "\"${var.otel_destination_header_value}\""
    }
  ] : []
}

# ---------------------------------------------------------------------------
# Worker Group
# ---------------------------------------------------------------------------
resource "criblio_group" "intake" {
  id                    = var.worker_group_id
  name                  = var.worker_group_id
  product               = "stream"
  on_prem               = var.on_prem
  is_fleet              = false
  worker_remote_access  = true
  provisioned           = false

  # Cloud-managed infrastructure sizing — not applicable on-prem, where the
  # Worker Group runs on infrastructure you already control (e.g. Docker).
  estimated_ingest_rate = var.on_prem ? null : 2048 # ~24 MB/s @ 9 worker processes

  cloud = var.on_prem ? null : {
    provider = "aws"
    region   = var.worker_group_region
  }
}

# ---------------------------------------------------------------------------
# Source: Syslog (TCP)
#
# KNOWN LIMITATION: TLS is disabled here for local demo/testing simplicity.
# A production deployment handling ePHI/PII in transit MUST enable the
# tls block below (SC-8 / 164.312(e)(1) — see README "Known Limitations").
# ---------------------------------------------------------------------------
resource "criblio_source" "syslog" {
  id       = "in-syslog-intake"
  group_id = criblio_group.intake.id

  input_syslog = {
    id             = "in-syslog-intake"
    type           = "syslog"
    host           = "0.0.0.0"
    tcp_port       = var.syslog_port
    disabled       = false
    send_to_routes = true
    tls = {
      disabled = true
    }
  }

  depends_on = [criblio_group.intake]
}

# ---------------------------------------------------------------------------
# Source: OpenTelemetry (OTLP)
#
# Receives traces, metrics, and logs over OTLP (gRPC by default) and
# extracts each span / metric data point / log record into its own event,
# so downstream Routes and Pipelines can treat telemetry the same way they
# treat any other event.
#
# KNOWN LIMITATION: see README — TLS is disabled here for the same
# demo-simplicity reason as the Syslog Source, which means the bearer
# token below would travel in the clear. Fine for a local/private test;
# never do this in production.
# ---------------------------------------------------------------------------
resource "criblio_source" "otel" {
  id       = "in-otel-intake"
  group_id = criblio_group.intake.id

  input_open_telemetry = {
    id             = "in-otel-intake"
    type           = "open_telemetry"
    host           = "0.0.0.0"
    port           = var.otel_port
    protocol       = var.otel_protocol
    otlp_version   = "1.3.1"
    extract_spans  = true
    extract_metrics = true
    extract_logs   = true
    disabled       = false
    send_to_routes = true

    auth_type = var.otel_bearer_token != "" ? "token" : "none"
    token     = var.otel_bearer_token != "" ? var.otel_bearer_token : null

    metadata = [
      {
        name  = "telemetry_type"
        value = "\"otel\""
      }
    ]

    tls = {
      disabled = true
    }
  }

  depends_on = [criblio_group.intake]
}

# ---------------------------------------------------------------------------
# Pipeline: two-stage data minimization
#
#   Stage 1 (mask_direct_identifiers) — regex-redacts direct identifiers
#     (SSN, email address) out of the raw event body before anything else
#     touches it. Maps to the HIPAA de-identification standard.
#
#   Stage 2 (allowlist_fields) — drops every field except an explicit,
#     documented allowlist. Maps to the HIPAA Minimum Necessary Standard /
#     NIST 800-53 data-minimization controls: nothing leaves this pipeline
#     that wasn't deliberately kept.
# ---------------------------------------------------------------------------
resource "criblio_pipeline" "minimize" {
  id       = "pipe-minimize-intake"
  group_id = criblio_group.intake.id

  conf = {
    description         = "Redacts direct identifiers, then allowlists fields before events leave Cribl."
    async_func_timeout   = 1000
    functions = [
      {
        id       = "eval"
        filter   = "true"
        disabled = false
        conf = jsonencode({
          add = [
            {
              name     = "_raw"
              value    = "_raw.replace(/\\b\\d{3}-\\d{2}-\\d{4}\\b/g, '[SSN-REDACTED]')"
              disabled = false
            }
          ]
        })
      },
      {
        id       = "eval"
        filter   = "true"
        disabled = false
        conf = jsonencode({
          add = [
            {
              name     = "_raw"
              value    = "_raw.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g, '[EMAIL-REDACTED]')"
              disabled = false
            }
          ]
        })
      },
      {
        id       = "eval"
        filter   = "true"
        disabled = false
        final    = true
        conf = jsonencode({
          remove = ["*"]
          keep   = ["_raw", "_time", "host", "source", "sourcetype"]
        })
      },
    ]
  }

  depends_on = [criblio_group.intake]
}

# ---------------------------------------------------------------------------
# Destination: S3 (encrypted at rest)
# ---------------------------------------------------------------------------
resource "criblio_destination" "s3" {
  id       = "out-s3-minimized"
  group_id = criblio_group.intake.id

  output_s3 = {
    id                     = "out-s3-minimized"
    type                   = "s3"
    bucket                 = var.aws_bucket_name
    region                 = var.aws_region
    aws_api_key            = var.aws_api_key
    aws_secret_key         = var.aws_secret_key
    stage_path             = "/tmp/cribl_stage"
    compress               = "gzip"
    compression_level      = "best_speed"
    empty_dir_cleanup_sec  = 300
    server_side_encryption = local.s3_server_side_encryption
    kms_key_id             = var.kms_key_id != "" ? var.kms_key_id : null
  }

  depends_on = [criblio_group.intake]
}

# ---------------------------------------------------------------------------
# Destination: OpenTelemetry (OTLP export)
#
# Forwards extracted spans/metrics/logs to any OTLP-compatible observability
# backend — Grafana Cloud, Honeycomb, Datadog's OTLP intake, or a self-hosted
# otel-collector. Point var.otel_destination_endpoint at whichever backend
# you're demoing against.
# ---------------------------------------------------------------------------
resource "criblio_destination" "otel_export" {
  id       = "out-otel-export"
  group_id = criblio_group.intake.id

  output_open_telemetry = {
    id           = "out-otel-export"
    type         = "open_telemetry"
    protocol     = var.otel_destination_protocol
    endpoint     = var.otel_destination_endpoint
    otlp_version = "1.3.1"
    auth_type    = "none" # auth (if any) is carried as a header in metadata below
    metadata     = local.otel_destination_metadata
  }

  depends_on = [criblio_group.intake]
}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
resource "criblio_routes" "main" {
  group_id = criblio_group.intake.id
  id       = "default" # routing table ID — Cribl requires this literal value

  routes = [
    {
      name        = "syslog-to-minimized-s3"
      description = "Syslog intake -> mask/allowlist pipeline -> encrypted S3"
      pipeline    = criblio_pipeline.minimize.id
      output      = criblio_destination.s3.id
      filter      = "__inputId=='in-syslog-intake'"
      final       = true
      disabled    = false
    },
    {
      name        = "otel-to-export"
      description = "OTLP intake (spans/metrics/logs) -> pass-through -> external OTLP backend"
      pipeline    = "main"
      output      = criblio_destination.otel_export.id
      filter      = "__inputId=='in-otel-intake'"
      final       = true
      disabled    = false
    },
    {
      name     = "default"
      pipeline = "main"
      output   = "default"
      filter   = "true"
      final    = false
      disabled = false
    },
  ]

  depends_on = [
    criblio_source.syslog,
    criblio_source.otel,
    criblio_destination.s3,
    criblio_destination.otel_export,
    criblio_pipeline.minimize,
  ]
}

# ---------------------------------------------------------------------------
# Commit + Deploy
#
# Every terraform apply produces a Cribl commit (versioned, auditable —
# maps to Audit Controls, 164.312(b) / NIST 800-53 AU-2/AU-3) and deploys
# that exact version to the Worker Group.
# ---------------------------------------------------------------------------
resource "criblio_commit" "intake" {
  effective = true
  group     = criblio_group.intake.id
  message   = "terraform apply: syslog intake -> mask/allowlist -> encrypted S3; otel intake -> OTLP export"

  depends_on = [criblio_routes.main]
}

data "criblio_config_version" "latest" {
  id         = criblio_group.intake.id
  depends_on = [criblio_commit.intake]
}

resource "criblio_deploy" "intake" {
  id      = criblio_group.intake.id
  version = data.criblio_config_version.latest.items[0]
}
