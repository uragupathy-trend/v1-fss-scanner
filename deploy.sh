#!/bin/bash

# Vision One File Security Scanner - OCI Deployment Script
# This script deploys the FSS scanner function to Oracle Cloud Infrastructure

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/terraform"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check required tools
    local tools=("terraform" "docker" "oci")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed or not in PATH"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check Terraform configuration
    if [[ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]]; then
        log_error "terraform.tfvars not found in $TERRAFORM_DIR"
        log_info "Please copy terraform.tfvars.example and configure it"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Validate terraform configuration
validate_configuration() {
    log_info "Validating Terraform configuration..."
    
    # Check if terraform.tfvars exists and has required values
    if [[ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]]; then
        log_error "terraform.tfvars not found in $TERRAFORM_DIR"
        log_info "Please copy terraform.tfvars.example and configure it with your values"
        exit 1
    fi
    
    # Basic validation that key variables are not placeholder values
    local placeholder_check=$(grep -E "(your-|aaaaaaaa|aa:bb:cc)" "$TERRAFORM_DIR/terraform.tfvars" | wc -l)
    if [[ $placeholder_check -gt 0 ]]; then
        log_warn "terraform.tfvars contains placeholder values. Please update with your actual configuration."
        log_info "Check the following variables in terraform.tfvars:"
        log_info "  - tenancy_ocid, user_ocid, fingerprint, private_key_path"
        log_info "  - compartment_id, subnet_id"
        log_info "  - bucket names, vision_one_api_key"
        log_info "  - docker_username, docker_auth_token, ocir_region"
    fi
    
    log_info "Configuration validation completed"
}

# Deploy infrastructure
deploy_infrastructure() {
    log_info "Deploying infrastructure with Terraform..."
    
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform
    log_info "Initializing Terraform..."
    terraform init
    
    # Plan deployment
    log_info "Planning deployment..."
    terraform plan -out=tfplan
    
    # Apply deployment
    log_info "Applying deployment..."
    terraform apply tfplan
    
    # Clean up plan file
    rm -f tfplan
    
    log_info "Infrastructure deployment completed"
}

# Display deployment summary
show_summary() {
    log_info "Deployment Summary:"
    
    cd "$TERRAFORM_DIR"
    
    echo "=================================="
    echo "Function Application:"
    terraform output -raw function_application_id 2>/dev/null || echo "  Not available"
    
    echo "Function ID:"
    terraform output -raw function_id 2>/dev/null || echo "  Not available"
    
    echo "Event Rule ID:"
    terraform output -raw event_rule_id 2>/dev/null || echo "  Not available"
    
    echo "OCIR Repository:"
    terraform output -raw ocir_repository_url 2>/dev/null || echo "  Not available"
    echo "=================================="
    
    log_info "Deployment completed successfully!"
    log_info "Upload a file to your source bucket to test the scanner"
}

# Main deployment function
main() {
    log_info "Starting Vision One File Security Scanner deployment..."
    
    check_prerequisites
    validate_configuration
    deploy_infrastructure
    show_summary
}

# Handle script interruption
trap 'log_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"
