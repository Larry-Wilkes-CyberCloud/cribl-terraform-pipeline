output "worker_group_id" {
  description = "ID of the Worker Group created by this project."
  value       = criblio_group.intake.id
}

output "syslog_listener" {
  description = "host:port the Syslog Source listens on."
  value       = "0.0.0.0:${var.syslog_port}"
}

output "pipeline_id" {
  description = "ID of the mask/allowlist pipeline."
  value       = criblio_pipeline.minimize.id
}

output "destination_bucket" {
  description = "S3 bucket receiving minimized, encrypted events."
  value       = var.aws_bucket_name
}

output "otel_listener" {
  description = "host:port the OpenTelemetry Source listens on (OTLP)."
  value       = "0.0.0.0:${var.otel_port} (${var.otel_protocol})"
}

output "otel_export_endpoint" {
  description = "OTLP endpoint extracted spans/metrics/logs are exported to."
  value       = var.otel_destination_endpoint
}

output "deployed_config_version" {
  description = "Config version deployed to the Worker Group by this apply."
  value       = data.criblio_config_version.latest.items[0]
}
