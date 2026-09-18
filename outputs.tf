output "worker_group_id" {
  description = "Cribl group ID resources are provisioned into (the standalone instance's built-in \"default\" group -- see main.tf's top-of-file note)."
  value       = var.worker_group_id
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

output "assurance_check_output_dir" {
  description = "Local directory pipeline-assurance-monitor's check_dependencies.py should poll for canary output."
  value       = var.assurance_check_dest_path
}
