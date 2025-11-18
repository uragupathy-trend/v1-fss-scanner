# Output values for the V1 File Security Scanner deployment

# OCIR Repository Outputs
output "ocir_repository_id" {
  description = "OCID of the OCIR repository"
  value       = oci_artifacts_container_repository.v1_fss_repo.id
}

output "ocir_repository_name" {
  description = "Name of the OCIR repository"
  value       = oci_artifacts_container_repository.v1_fss_repo.display_name
}

output "container_image_url" {
  description = "Full container image URL"
  value       = "${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_repo.display_name}:${var.image_tag}"
}

# Function Application Outputs
output "function_application_id" {
  description = "OCID of the function application"
  value       = oci_functions_application.v1_fss_application.id
}

output "function_application_name" {
  description = "Name of the function application"
  value       = oci_functions_application.v1_fss_application.display_name
}

# Function Outputs
output "function_id" {
  description = "OCID of the function"
  value       = oci_functions_function.v1_fss_function.id
}

output "function_name" {
  description = "Name of the function"
  value       = oci_functions_function.v1_fss_function.display_name
}

output "function_invoke_endpoint" {
  description = "Function invoke endpoint"
  value       = oci_functions_function.v1_fss_function.invoke_endpoint
}

# Event Rule Outputs
output "event_rule_id" {
  description = "OCID of the event rule"
  value       = oci_events_rule.v1_fss_event_rule.id
}

output "event_rule_name" {
  description = "Name of the event rule"
  value       = oci_events_rule.v1_fss_event_rule.display_name
}

# Dynamic Group and Policy Outputs
output "dynamic_group_id" {
  description = "OCID of the dynamic group"
  value       = oci_identity_dynamic_group.v1_fss_function_dynamic_group.id
}

output "dynamic_group_name" {
  description = "Name of the dynamic group"
  value       = oci_identity_dynamic_group.v1_fss_function_dynamic_group.name
}

output "function_policy_id" {
  description = "OCID of the function policy"
  value       = oci_identity_policy.v1_fss_function_policy.id
}

# Logging Outputs (conditional)
output "log_group_id" {
  description = "OCID of the log group (if logging is enabled)"
  value       = var.enable_logging ? oci_logging_log_group.v1_fss_log_group[0].id : "Logging disabled"
}

output "logging_status" {
  description = "Status of logging configuration"
  value       = var.enable_logging ? "Enabled" : "Disabled"
}

# Bucket Configuration (existing buckets)
output "bucket_configuration" {
  description = "Bucket configuration for file processing"
  value = {
    source_bucket      = var.source_bucket_name
    production_bucket  = var.production_bucket_name
    quarantine_bucket  = var.quarantine_bucket_name
  }
}

# Function Configuration
output "function_configuration" {
  description = "Function configuration details"
  value = {
    memory_mb          = var.function_memory_mb
    timeout_seconds    = var.function_timeout_seconds
    image_tag          = var.image_tag
    vision_one_region  = var.vision_one_region
    environment        = var.environment
  }
}

# Deployment Summary
output "deployment_summary" {
  description = "Complete deployment summary"
  value = {
    status = "SUCCESS"
    components = {
      ocir_repository = oci_artifacts_container_repository.v1_fss_repo.display_name
      function_app    = oci_functions_application.v1_fss_application.display_name
      function        = oci_functions_function.v1_fss_function.display_name
      event_rule      = oci_events_rule.v1_fss_event_rule.display_name
      dynamic_group   = oci_identity_dynamic_group.v1_fss_function_dynamic_group.name
      policy          = oci_identity_policy.v1_fss_function_policy.name
    }
    configuration = {
      source_bucket      = var.source_bucket_name
      production_bucket  = var.production_bucket_name
      quarantine_bucket  = var.quarantine_bucket_name
      vision_one_region  = var.vision_one_region
      container_image    = "${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_repo.display_name}:${var.image_tag}"
    }
  }
}

# Next Steps
output "next_steps" {
  description = "Instructions for testing and using the deployed scanner"
  value = <<-EOT
    
    🎉 Vision One File Security Scanner deployed successfully!
    
    📋 TESTING INSTRUCTIONS:
    1. Upload a test file to the source bucket: ${var.source_bucket_name}
    2. Monitor function execution in OCI Console:
       - Go to Developer Services > Functions
       - Select application: ${oci_functions_application.v1_fss_application.display_name}
       - Select function: ${oci_functions_function.v1_fss_function.display_name}
       - Check Logs tab for scan results
    
    📊 MONITORING:
    - Function logs: ${var.enable_logging ? "Enabled" : "Disabled"}
    - Event rule: ${oci_events_rule.v1_fss_event_rule.display_name}
    - Trigger: Object uploads to ${var.source_bucket_name}
    
    📁 FILE FLOW:
    - Clean files → ${var.production_bucket_name}
    - Malware detected → ${var.quarantine_bucket_name}
    
    🔧 CONFIGURATION:
    - Container image: ${var.ocir_region}/${var.tenancy_namespace}/${oci_artifacts_container_repository.v1_fss_repo.display_name}:${var.image_tag}
    - Memory: ${var.function_memory_mb}MB
    - Timeout: ${var.function_timeout_seconds}s
    - Vision One region: ${var.vision_one_region}
    
  EOT
}
