# Vision One File Security Scanner for OCI

Automated file security scanning solution for Oracle Cloud Infrastructure (OCI) using Trend Micro Vision One File Security SDK. Files uploaded to a source bucket are automatically scanned for malware and moved to appropriate buckets based on scan results.

## Architecture

```
Source Bucket → OCI Event Rule → OCI Function → Vision One API
                                      ↓
                            Clean Files → Production Bucket
                            Malware → Quarantine Bucket
```

## Prerequisites

### Required Tools
- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Docker](https://docs.docker.com/get-docker/)
- [OCI CLI](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm)

### OCI Resources
- OCI Tenancy with appropriate permissions
- Compartment for deploying resources
- VCN with subnet for function deployment
- Three existing Object Storage buckets:
  - Source bucket (where files are uploaded)
  - Production bucket (for clean files)
  - Quarantine bucket (for files with malware)

### Vision One Requirements
- Trend Micro Vision One account
- Vision One API key with "Run file scan via SDK" permission
- Vision One region (e.g., ap-southeast-2)

### OCI Vault Setup 
Setup OCI Vault to store Vision One API Key credentials:

1. **Create a Vault** (if not already available):
   ```bash
   oci kms management vault create \
     --compartment-id <compartment-ocid> \
     --display-name "v1-fss-vault" \
     --vault-type DEFAULT
   ```

2. **Create a Master Encryption Key**:
   ```bash
   oci kms management key create \
     --compartment-id <compartment-ocid> \
     --display-name "v1-fss-key" \
     --key-shape '{"algorithm":"AES","length":32}' \
     --endpoint <vault-management-endpoint>
   ```

3. **Create a Secret for Vision One API Key**:
   ```bash
   oci vault secret create-base64 \
     --compartment-id <compartment-ocid> \
     --secret-name "vision-one-api-key" \
     --vault-id <vault-ocid> \
     --key-id <key-ocid> \
     --secret-content-content <base64-encoded-api-key>
   ```

4. **Note the Secret OCID** for use in terraform.tfvars

5. **Emit object events is enabled for the bucket to be scanned**

   Go to the bucket details enable Emit object events if it disabled

## Quick Start

### 1. Configure Terraform Variables

Copy and edit the configuration file:

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

Edit `terraform/terraform.tfvars` with your values:

```hcl
# OCI Authentication
tenancy_ocid     = "ocid1.tenancy.oc1..aaaaaaaa..."
user_ocid        = "ocid1.user.oc1..aaaaaaaa..."
fingerprint      = "aa:bb:cc:dd:ee:ff:gg:hh:ii:jj:kk:ll:mm:nn:oo:pp"
private_key_path = "~/.oci/oci_api_key.pem"
region           = "ap-sydney-1"

# Compartment and Network
compartment_id = "ocid1.compartment.oc1..aaaaaaaa..."
subnet_id      = "ocid1.subnet.oc1.ap-sydney-1.aaaaaaaa..."

# Existing Bucket Names
source_bucket_name      = "your-source-bucket"
production_bucket_name  = "your-production-bucket"
quarantine_bucket_name  = "your-quarantine-bucket"

# Vision One Configuration (using OCI Vault)
vision_one_api_key_secret_ocid = "ocid1.vaultsecret.oc1.ap-sydney-1.aaaaaaaa..."
vision_one_region = "ap-southeast-2"

# Docker/OCIR Configuration
docker_username = "your-tenancy-namespace/your-username"
docker_auth_token = "your-oci-auth-token"
ocir_region = "syd.ocir.io"
```

### 2. Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

The deployment script will:
- Check prerequisites (Terraform, Docker, OCI CLI)
- Validate Terraform configuration
- Build and push Docker image to OCIR
- Deploy all infrastructure with Terraform
- Provide deployment summary

## What Gets Created

- **OCIR Repository** - Container registry for the function image
- **Function Application** - OCI Functions application with GENERIC_X86 shape
- **Function** - The malware scanning function
- **Event Rule** - Triggers function on object uploads to source bucket
- **Dynamic Group & IAM Policy** - Permissions for function execution
- **Log Group & Logs** - Logging for events and function execution

## How It Works

1. **File Upload** → User uploads file to source bucket
2. **Event Trigger** → OCI Events detects upload and triggers function
3. **File Download** → Function downloads file to temporary storage
4. **Malware Scan** → File scanned using Vision One File Security SDK
5. **Result Processing** → Based on scan results:
   - **Clean files** → Moved to production bucket with metadata tags
   - **Malware detected** → Moved to quarantine bucket with metadata tags
6. **Cleanup** → Temporary files cleaned up automatically

## File Tagging

Files are automatically tagged with scan results:

### Clean Files
```json
{
  "filescanned": "true",
  "ismalwaredetected": "false",
  "scanid": "uuid-of-scan",
  "scannerversion": "1.0.0",
  "scantimestamp": "1641234567"
}
```

### Files with Malware
```json
{
  "filescanned": "true",
  "ismalwaredetected": "true",
  "scanid": "uuid-of-scan",
  "scannerversion": "1.0.0",
  "scantimestamp": "1641234567",
  "malwarenames": "Trojan.Win32.Example"
}
```

## Testing

1. Upload a test file to your source bucket
2. Monitor function execution in OCI Console → Developer Services → Functions
3. Check scan results in function logs
4. Verify file movement to production or quarantine bucket
5. Check file metadata tags for scan results

## Troubleshooting

### Common Issues

**Deployment Failures**
- Verify Terraform, Docker, and OCI CLI are installed
- Check OCI CLI configuration: `oci setup config`
- Ensure Docker daemon is running: `docker info`
- Verify terraform.tfvars is properly configured with your values

**Function Not Triggering**
- Check event rule is enabled in OCI Console
- Verify source bucket name matches configuration
- Ensure function has proper IAM permissions

**Scan Failures**
- Verify Vision One API key is valid and has correct permissions
- Check Vision One region configuration
- Ensure network connectivity to Vision One API

### Monitoring

View function logs in OCI Console:
1. Go to **Developer Services** → **Functions**
2. Select **v1-fss-application**
3. Select **v1-fss-scanner**
4. Click **Logs** tab

### Cleanup

To remove all deployed resources:

```bash
cd terraform
terraform destroy
```

## Configuration

### Function Settings
- **Memory**: 512 MB
- **Timeout**: 300 seconds (5 minutes)
- **Runtime**: Python 3.9
- **Shape**: GENERIC_X86 (x86_64 architecture)

### Environment Variables
The function uses these environment variables (automatically configured):

**Standard Configuration:**
- `SOURCE_BUCKET_NAME` - Source bucket for file uploads
- `PRODUCTION_BUCKET_NAME` - Destination for clean files
- `QUARANTINE_BUCKET_NAME` - Destination for files with malware
- `V1_REGION` - Vision One region
- `V1_SCANNER_ENDPOINT` - Vision One scanner endpoint

**Vault-based Configuration (when use_vault = true):**
- `V1_API_KEY_SECRET_OCID` - OCID of the secret containing Vision One API key

## Security

- Docker credentials managed as sensitive Terraform variables
- IAM policies follow least-privilege access principles
- All operations logged for audit trails
- Container images stored in private OCIR repository

---

For more information about Vision One File Security, visit the [official documentation](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-file-security).
