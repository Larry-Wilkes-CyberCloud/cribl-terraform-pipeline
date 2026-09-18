# cribl-terraform-pipeline
#
# Provisions a Syslog Source, an OpenTelemetry Source, a two-stage
# data-minimization Pipeline, an S3 Destination, and the Routes tying
# them together — entirely via Terraform, against a real distributed
# on-prem Cribl Stream deployment (a Leader + at least one Worker Node,
# both targeting the built-in "default" group).
#
# NOTE ON TOPOLOGY (2026-09-14): this project originally managed its own
# custom Worker Group ("cg-intake-hipaa-demo") via a criblio_group
# resource, on the assumption a Worker Node was already joined to it.
# Live testing found that assumption wrong -- the Docker container was a
# Leader (CRIBL_DIST_MODE=leader) with zero Workers ever connected, so
# nothing deployed to that custom group ever actually processed traffic;
# terraform apply/commit/deploy all reported success because the API
# accepted the config, it just had nowhere to run it. Standalone mode was
# tried and ruled out -- it gets data flowing, but the criblio provider
# only ever calls the distributed /m/<group>/... API surface, so it can't
# manage Sources/Pipelines/Destinations against a standalone instance at
# all. Fixed properly: stood up a real Worker Node joined to the
# instance's built-in "default" group (which exists on a Leader too, no
# custom group needed) and pointed every resource at that.
#
# NOTE ON __inputId (2026-09-14): the Routes below filter on __inputId,
# which is "<source type>:<source id>:<per-connection suffix>" -- not the
# bare Source id, and not even an exact "type:id" match. Two rounds of
# live confirmation, both in the Cribl UI's Routes table: (1) bare id
# ("in-syslog-intake") matched 0% of events, every event falling through
# to the "default" catch-all route to devnull, even with the Source
# confirmed receiving real data via Live Data capture; (2) exact equality
# on "syslog:in-syslog-intake" (no trailing suffix) STILL matched 0% --
# the actual proof came from Cribl's own auto-generated default filter
# for that Source's Live Data view, which reads literally
# `__inputId.startsWith('syslog:in-syslog-intake:')`. Routes now use
# startsWith with the trailing colon, matching Cribl's own convention.
#
# See README.md "Honesty note" for the full writeup of both bugs, and for
# the HIPAA / NIST 800-53 control mapping this pipeline is designed
# against.

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
# Source: Syslog (TCP)
#
# KNOWN LIMITATION: TLS is disabled here for local demo/testing simplicity.
# A production deployment handling ePHI/PII in transit MUST enable the
# tls block below (SC-8 / 164.312(e)(1) — see README "Known Limitations").
# ---------------------------------------------------------------------------
resource "criblio_source" "syslog" {
  id       = "in-syslog-intake"
  group_id = var.worker_group_id

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
  group_id = var.worker_group_id

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
  group_id = var.worker_group_id

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
        # DRIFT-DETECTION DEMO (2026-09-14) -- disabled by default
        # (var.enable_ip_redaction_demo = false). This is a deliberately
        # realistic future hardening change: redacting IPv4 addresses out
        # of _raw looks like a reasonable, unrelated security improvement,
        # but it destroys the src_ip token AC-7 and AC-7-followup's rex
        # depend on -- exactly the failure mode pipeline-assurance-monitor
        # exists to catch. Flip var.enable_ip_redaction_demo to true and
        # re-apply to prove check_dependencies.py catches it (expect AC-7
        # and AC-7-followup to FAIL, AC-6(9) to still PASS since it never
        # depended on src_ip); flip back and re-apply to restore the
        # working baseline. See pipeline-assurance-monitor/README.md for
        # the captured before/after results.
        id       = "eval"
        filter   = "true"
        disabled = !var.enable_ip_redaction_demo
        conf = jsonencode({
          add = [
            {
              name     = "_raw"
              value    = "_raw.replace(/\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b/g, '[IP-REDACTED]')"
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
}

# ---------------------------------------------------------------------------
# Destination: S3 (encrypted at rest)
# ---------------------------------------------------------------------------
resource "criblio_destination" "s3" {
  id       = "out-s3-minimized"
  group_id = var.worker_group_id

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
  group_id = var.worker_group_id

  output_open_telemetry = {
    id           = "out-otel-export"
    type         = "open_telemetry"
    protocol     = var.otel_destination_protocol
    endpoint     = var.otel_destination_endpoint
    otlp_version = "1.3.1"
    auth_type    = "none" # auth (if any) is carried as a header in metadata below
    metadata     = local.otel_destination_metadata
  }
}

# ---------------------------------------------------------------------------
# Destination: Filesystem (pipeline-assurance-monitor's canary check)
#
# Same masking/allowlist Pipeline as production traffic, different
# Destination -- gives the pipeline-assurance-monitor project a local,
# instantly-readable output to assert against, without ever landing test
# canary events in the real S3 bucket. See the Routes block below: canary
# events are matched and diverted here BEFORE the real syslog route, by a
# marker token (CANARY_) that real auth-log data will never contain.
# ---------------------------------------------------------------------------
resource "criblio_destination" "assurance_check" {
  id       = "out-fs-assurance-check"
  group_id = var.worker_group_id

  output_filesystem = {
    id                     = "out-fs-assurance-check"
    type                   = "filesystem"
    dest_path              = var.assurance_check_dest_path
    stage_path             = var.assurance_check_stage_path
    format                 = "json"
    compress               = "none"
    max_file_open_time_sec = 10 # provider's enforced minimum (10-1800s) -- still fast enough for a test script to wait on
    on_backpressure         = "block"
  }
}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
resource "criblio_routes" "main" {
  group_id = var.worker_group_id
  id       = "default" # routing table ID — Cribl requires this literal value

  routes = [
    {
      name        = "syslog-canary-to-assurance-check"
      description = "pipeline-assurance-monitor canary events (CANARY_ marker) -> same mask/allowlist pipeline as production -> local JSON file for automated drift checking. Must come BEFORE syslog-to-minimized-s3 below so canaries never reach real S3."
      pipeline    = criblio_pipeline.minimize.id
      output      = criblio_destination.assurance_check.id
      # __inputId is "<source type>:<source id>:<per-connection suffix>",
      # not the bare source id and not even an exact "type:id" match --
      # confirmed live (2026-09-14) two ways: (1) an exact-equality filter
      # on "syslog:in-syslog-intake" still matched 0% of events even though
      # the Source was confirmed receiving real data; (2) Cribl's OWN
      # auto-generated default filter for this exact Source's Live Data
      # view is literally `__inputId.startsWith('syslog:in-syslog-intake:')`
      # -- note the trailing colon, confirming there's a suffix after the
      # source id and that startsWith (not ==) is the correct match style.
      filter      = "__inputId.startsWith('syslog:in-syslog-intake:') && _raw.indexOf('CANARY_') !== -1"
      final       = true
      disabled    = false
    },
    {
      name        = "syslog-to-minimized-s3"
      description = "Syslog intake -> mask/allowlist pipeline -> encrypted S3"
      pipeline    = criblio_pipeline.minimize.id
      output      = criblio_destination.s3.id
      filter      = "__inputId.startsWith('syslog:in-syslog-intake:')"
      final       = true
      disabled    = false
    },
    {
      name        = "otel-to-export"
      description = "OTLP intake (spans/metrics/logs) -> pass-through -> external OTLP backend"
      pipeline    = "main"
      output      = criblio_destination.otel_export.id
      # Not yet independently confirmed for the OTel Source specifically
      # (only the Syslog Source's __inputId format was verified live) --
      # applying the same startsWith(<type>:<id>:) pattern proactively
      # since it's Cribl's general internal convention, but flagging this
      # one as unverified rather than assuming it's right.
      filter      = "__inputId.startsWith('open_telemetry:in-otel-intake:')"
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
    criblio_destination.assurance_check,
    criblio_pipeline.minimize,
  ]
}

# ---------------------------------------------------------------------------
# Commit + Deploy
#
# Every terraform apply produces a Cribl commit (versioned, auditable —
# maps to Audit Controls, 164.312(b) / NIST 800-53 AU-2/AU-3). On a
# standalone instance a commit takes effect immediately -- there's no
# separate Worker fleet to push a deploy to -- but criblio_deploy is left
# in place since the provider still exposes it as part of the commit
# workflow; if terraform plan/apply shows it as a no-op or unnecessary
# against this standalone instance, that's expected, and we'll drop it
# then rather than guess now.
# ---------------------------------------------------------------------------
resource "criblio_commit" "intake" {
  effective = true
  group     = var.worker_group_id
  message   = "terraform apply: syslog intake -> mask/allowlist -> encrypted S3; otel intake -> OTLP export"

  depends_on = [criblio_routes.main]
}

data "criblio_config_version" "latest" {
  id         = var.worker_group_id
  depends_on = [criblio_commit.intake]
}

resource "criblio_deploy" "intake" {
  id      = var.worker_group_id
  version = data.criblio_config_version.latest.items[0]
}
