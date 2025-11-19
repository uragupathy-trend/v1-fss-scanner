#!/bin/bash
# Vision One File Security Scanner - OCI Deployment Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/terraform"
OPERATION="deploy"
FORCE_MODE=false

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'

log() { echo -e "${2:-$G}[${3:-INFO}]$NC $1"; }
die() { log "$1" "$R" "ERROR"; exit 1; }

usage() {
    cat << EOF
Usage: $0 [deploy|destroy] [--force]

Commands:
  deploy    Deploy infrastructure (default)
  destroy   Destroy infrastructure
  help      Show this help

Options:
  --force   Skip confirmations (destroy only)

Examples:
  $0                  # Deploy
  $0 destroy          # Destroy with prompts
  $0 destroy --force  # Destroy without prompts
EOF
}

check_prereqs() {
    log "Checking prerequisites..."
    for tool in terraform docker oci; do
        command -v "$tool" >/dev/null || die "$tool not found in PATH"
    done
    docker info >/dev/null 2>&1 || die "Docker daemon not running"
    [[ -f "$TERRAFORM_DIR/terraform.tfvars" ]] || die "terraform.tfvars not found. Copy from terraform.tfvars.example"
    
    # Check for placeholder values
    if grep -qE "(your-|aaaaaaaa|aa:bb:cc)" "$TERRAFORM_DIR/terraform.tfvars" 2>/dev/null; then
        log "terraform.tfvars contains placeholder values. Update with actual configuration." "$Y" "WARN"
    fi
}

deploy() {
    log "Deploying infrastructure..." "$B"
    cd "$TERRAFORM_DIR"
    terraform init
    terraform plan -out=tfplan
    terraform apply tfplan
    rm -f tfplan
    
    log "Deployment Summary:" "$G"
    echo "=========================="
    echo "Function App: $(terraform output -raw function_application_id 2>/dev/null || echo "N/A")"
    echo "Function ID: $(terraform output -raw function_id 2>/dev/null || echo "N/A")"
    echo "Event Rule: $(terraform output -raw event_rule_id 2>/dev/null || echo "N/A")"
    echo "OCIR Repo: $(terraform output -raw ocir_repository_url 2>/dev/null || echo "N/A")"
    echo "=========================="
    log "Deployment complete! Upload a file to test the scanner."
}

destroy() {
    log "WARNING: This will destroy ALL infrastructure!" "$Y" "WARN"
    echo "  - OCI Function and Application"
    echo "  - Event Rules and Triggers"
    echo "  - Container Images from OCIR"
    echo "  - IAM Policies and Dynamic Groups"
    
    if [[ "$FORCE_MODE" != "true" ]]; then
        read -p "Type 'yes' to confirm: " confirm
        [[ "$confirm" == "yes" ]] || { log "Cancelled"; exit 0; }
        read -p "Type 'DELETE' for final confirmation: " final
        [[ "$final" == "DELETE" ]] || { log "Cancelled"; exit 0; }
    fi
    
    log "Destroying infrastructure..." "$Y" "WARN"
    cd "$TERRAFORM_DIR"
    [[ -d ".terraform" ]] || terraform init
    terraform plan -destroy -out=destroy.tfplan
    terraform apply destroy.tfplan
    rm -f destroy.tfplan
    log "All resources destroyed" "$Y" "WARN"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        deploy) OPERATION="deploy"; shift ;;
        destroy) OPERATION="destroy"; shift ;;
        --force) FORCE_MODE=true; shift ;;
        help|--help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1. Use --help for usage."; ;;
    esac
done

trap 'die "Operation interrupted"' INT TERM

log "Starting $OPERATION operation..." "$B"
check_prereqs

case $OPERATION in
    deploy) deploy ;;
    destroy) destroy ;;
    *) die "Invalid operation: $OPERATION" ;;
esac
