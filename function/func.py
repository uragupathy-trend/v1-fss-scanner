import io
import json
import logging
import os
import tempfile
import time
from typing import Dict, Any
import base64

from fdk import response
import oci
from oci.vault import VaultsClient
from oci.secrets import SecretsClient

import amaas.grpc

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global cache for secrets to avoid repeated vault calls
_secret_cache = {}

def get_secret_from_vault(secret_ocid: str, signer) -> str:
    """Retrieve secret from OCI Vault with caching"""
    
    # Check cache first
    if secret_ocid in _secret_cache:
        logger.info(f"Using cached secret for OCID: {secret_ocid[:20]}...")
        return _secret_cache[secret_ocid]
    
    try:
        logger.info(f"Retrieving secret from vault: {secret_ocid[:20]}...")
        
        # Initialize secrets client
        secrets_client = SecretsClient(config={}, signer=signer)
        
        # Get secret bundle (current version)
        secret_bundle = secrets_client.get_secret_bundle(secret_id=secret_ocid)
        
        # Decode the secret content
        secret_content = secret_bundle.data.secret_bundle_content.content
        #decoded_secret = base64.b64decode(secret_content).decode('utf-8')
        
        # Cache the secret
        _secret_cache[secret_ocid] = secret_content
        
        logger.info("Secret retrieved and cached successfully")
        return secret_content
        
    except Exception as e:
        logger.error(f"Error retrieving secret from vault: {str(e)}")
        raise ValueError(f"Failed to retrieve secret from vault: {str(e)}")

def handler(ctx, data: io.BytesIO = None):
    """
    OCI Function handler for Vision One File Security scanning
    
    This function is triggered by OCI Events when an object is uploaded to a bucket.
    It downloads the file, scans it using Vision One File Security SDK, and moves
    the file to either production or quarantine bucket based on scan results.
    """
    try:
        # Parse the event data
        event_data = json.loads(data.getvalue())
        logger.info(f"Received event: {json.dumps(event_data, indent=2)}")

        # Extract event information
        event_type = event_data.get('eventType', '')
        logger.info(f"Event type: {event_type}")
        # Check if it's an object create event
        # Check if it's an object create event
        if event_type == 'com.oraclecloud.objectstorage.createobject' or \
        'com.oraclecloud.objectstorage.createobject' in event_type or \
        event_type.endswith('createobject'):

            # Extract object details
            resource_name = event_data.get('data', {}).get('resourceName', '')
            bucket_name = event_data.get('data', {}).get('additionalDetails', {}).get('bucketName', '')
            namespace = event_data.get('data', {}).get('additionalDetails', {}).get('namespace', '')
            
            # Log the event
            logger.info(f"Object Create Event Detected:")
            logger.info(f"  Bucket: {bucket_name}")
            logger.info(f"  Object: {resource_name}")
            logger.info(f"  Namespace: {namespace}")
            logger.info(f"  Event Type: {event_type}")

            logger.info("Creating OCI Object Storage Client")
            # Initialize OCI client with resource principal authentication
            signer = oci.auth.signers.get_resource_principals_signer()
            object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)

            logger.info("OCI Object Storage Client created successfully")
            # Get namespace for object storage operations
            namespace = object_storage_client.get_namespace().data
            logger.info(f"Namespace: {namespace}")

            # Get configuration from environment variables
            config = get_configuration()

            logger.info(f"Configuration - Source Bucket: {config['source_bucket_name']}")
            # Only process files from the source bucket
            if bucket_name != config['source_bucket_name']:
                logger.info(f"Ignoring file from bucket: {bucket_name} (not source bucket)")
                return {"status": "ignored", "reason": "Not from source bucket"}

            # Download and scan the file
            scan_result = download_and_scan_file(
                object_storage_client, 
                namespace, 
                bucket_name, 
                resource_name, 
                config
            )

            logger.info(f"Scan Result: {scan_result}")

            # Move file based on scan results
            move_result = move_file_based_on_scan(
                object_storage_client,
                namespace,
                bucket_name,
                resource_name,
                scan_result,
                config
            )
            
            logger.info(f"Processing completed successfully: {move_result}")
            
            
            return response.Response(
                ctx, 
                response_data=json.dumps({
                    "status": "success",
                    "scan_result": scan_result,
                    "move_result": move_result,
                    "message": "Object create event logged",
                    "bucket": bucket_name,
                    "object": resource_name
                }),
                headers={"Content-Type": "application/json"}
            )
        else:
            logger.info(f"Ignoring event type: {event_type}")
            return response.Response(
                ctx,
                response_data=json.dumps({"status": "ignored", "event_type": event_type}),
                headers={"Content-Type": "application/json"}
            )
            
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return response.Response(
            ctx,
            response_data=json.dumps({"status": "error", "error": str(e)}),
            headers={"Content-Type": "application/json"},
            status_code=500
        )
    
def get_configuration() -> Dict[str, str]:
    """Get configuration from environment variables and OCI Vault"""
    
    # Initialize OCI signer for vault access
    signer = oci.auth.signers.get_resource_principals_signer()
    
    # Standard environment variables (non-sensitive)
    standard_vars = [
        'SOURCE_BUCKET_NAME',
        'PRODUCTION_BUCKET_NAME', 
        'QUARANTINE_BUCKET_NAME',
        'V1_REGION',
        'V1_SCANNER_ENDPOINT'
    ]
    
    # Vault-based variables (sensitive)
    vault_vars = [
        'VAULT_SECRET_OCID'
    ]
    
    config = {}
    
    # Get standard configuration from environment variables
    for var in standard_vars:
        value = os.environ.get(var)
        if not value:
            raise ValueError(f"Missing required environment variable: {var}")
        config[var.lower()] = value
    
    # Get sensitive configuration from OCI Vault
    for var in vault_vars:
        secret_ocid = os.environ.get(var)
        if not secret_ocid:
            raise ValueError(f"Missing required environment variable: {var}")
        
        if var == 'VAULT_SECRET_OCID':
            # Retrieve Vision One API key from vault
            api_key = get_secret_from_vault(secret_ocid, signer)
            config['v1_api_key'] = api_key
    
    return config

def download_and_scan_file(
    client: oci.object_storage.ObjectStorageClient,
    namespace: str,
    bucket_name: str,
    object_name: str,
    config: Dict[str, str]
) -> Dict[str, Any]:
    """Download file and scan with Vision One File Security"""
    
    # Create temp file with original filename in /tmp
    temp_file_path = f"/tmp/{os.path.basename(object_name)}"
    
    try:
        # Download object to temporary file
        logger.info(f"Downloading object: {object_name}")
        get_object_response = client.get_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=object_name
        )
        
        # Write object data to file in /tmp
        with open(temp_file_path, 'wb') as temp_file:
            for chunk in get_object_response.data.raw.stream(1024 * 1024, decode_content=False):
                temp_file.write(chunk)
        
        logger.info(f"File downloaded to: {temp_file_path}")
        
        # Scan file with Vision One File Security
        scan_result = scan_file_with_vision_one(temp_file_path, config)
        
        return scan_result
        
    finally:
        # Clean up temporary file
        try:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                logger.info("Temporary file cleaned up")
        except Exception as e:
            logger.warning(f"Failed to clean up temporary file: {e}")

def scan_file_with_vision_one(file_path: str, config: Dict[str, str]) -> Dict[str, Any]:
    """Scan file using Vision One File Security SDK"""
    
    api_key = config['v1_api_key']
    region = config['v1_region']
    endpoint = config['v1_scanner_endpoint']    
    logger.info(f"Initializing Vision One File Security client for region: {region}")
    
    try:
        # Initialize Vision One File Security handle
        #handle = amaas.grpc.init_by_region(region=region, api_key=api_key, enable_tls=True, ca_cert=None)
        handle = amaas.grpc.init(host=endpoint, api_key=api_key, enable_tls=False, ca_cert=None)
        
        # Perform file scan
        start_time = time.perf_counter()
        logger.info(f"Starting scan of file: {file_path}")
        
        result = amaas.grpc.scan_file(
            channel=handle,
            file_name=file_path,
            tags=["oci-function", "automated-scan"],
            verbose=True
        )
        
        elapsed_time = time.perf_counter() - start_time
        logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        
        # Parse scan result
        scan_data = json.loads(result)
        is_malware_detected = False

        logger.info(f"Scan Data: {scan_data}")
        
        atse_result = scan_data.get('result', {}).get('atse', {})
        if atse_result:
            malware_count = atse_result.get('malwareCount', 0)
            logger.info(f"Malware Count: {malware_count}")
            malware_list = atse_result.get('malware', [])
            logger.info(f"Malware List: {malware_list}")
            is_malware_detected = malware_count > 0
            logger.info(f"Is Malware Detected: {is_malware_detected}")
            
        else:
            logger.error("No 'atse' result found in scan data")
        
        return {
            "is_malware_detected": is_malware_detected,
            "scan_id": scan_data.get('scanId'),
            "file_sha256": scan_data.get('fileSHA256'),
            "scanner_version": scan_data.get('scannerVersion'),
            "elapsed_time": elapsed_time,
        }
        
    except Exception as e:
        logger.error(f"Error during Vision One scan: {str(e)}")
        raise
    finally:
        # Clean up Vision One handle
        try:
            amaas.grpc.quit(handle)
        except:
            pass     

def move_file_based_on_scan(
    client: oci.object_storage.ObjectStorageClient,
    namespace: str,
    source_bucket: str,
    object_name: str,
    scan_result: Dict[str, Any],
    config: Dict[str, str]
) -> Dict[str, Any]:
    """Move file to appropriate bucket and update tags based on scan results"""
    
    is_malware_detected = scan_result['is_malware_detected']
    target_bucket = config['quarantine_bucket_name'] if is_malware_detected else config['production_bucket_name']
    
    logger.info(f"Moving file to {'quarantine' if is_malware_detected else 'production'} bucket: {target_bucket}")
    
    try:
        # Get the original object
        get_object_response = client.get_object(
            namespace_name=namespace,
            bucket_name=source_bucket,
            object_name=object_name
        )
        
        # Get existing freeform tags from source object
        existing_tags = {}
        try:
            object_details = client.head_object(
                namespace_name=namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            existing_tags = object_details.headers.get('opc-freeform-tags', {})
            if isinstance(existing_tags, str):
                existing_tags = json.loads(existing_tags)
        except:
            existing_tags = {}

        # Prepare scan result tags
        scan_tags = {
            "fileccanned": "true",
            "ismalwaredetected": str(is_malware_detected).lower(),
            "scantimestamp": str(int(time.time())),
            "scanid": scan_result.get('scan_id', ''),
            "scannerversion": scan_result.get('scanner_version', '')
        }

        if is_malware_detected:
            malware_names = ",".join([m.get('malwareName', '') for m in scan_result.get('found_malwares', [])])
            scan_tags["MalwareNames"] = malware_names[:200]  # Limit tag value
   
        try:
            # Copy object to target bucket with  tags and metadata
            logger.info(f"Copying object to target bucket: {target_bucket}")
            
            copy_response = client.put_object(
                namespace_name=namespace,
                bucket_name=target_bucket,
                object_name=object_name,
                put_object_body=get_object_response.data.content,
                content_type=get_object_response.headers.get('content-type'),
                opc_meta={
                    **scan_tags,
                    "originalbucket": source_bucket
                }
            )
            
            logger.info(f"Object successfully copied to target bucket - copy response: {copy_response.headers}")
           
        except Exception as copy_error:
            logger.error(f"Error copying object: {str(copy_error)}")

            # Update source object with error information
            client.put_object(
                namespace_name=namespace,
                bucket_name=source_bucket,
                object_name=object_name,
                put_object_body=get_object_response.data.content,
                content_type=get_object_response.headers.get('content-type'),
                opc_meta={
                    "copy-error": str(copy_error)[:500],
                    "error-timestamp": str(int(time.time()))
                }
            )
            
            logger.info("Error details added to source object")
            return {
                "action": "copy_failed",
                "source_bucket": source_bucket,
                "target_bucket": target_bucket,
                "object_name": object_name,
                "error": str(copy_error)
            }
        
        logger.info(f"Deleting the object from the source bucket: {source_bucket} after successfully copying to the target bucket {target_bucket}")
        # delete the object from the source bucket
        delete_response = client.delete_object(
            namespace_name=namespace,
            bucket_name=source_bucket,
            object_name=object_name
        )
        logger.info(f"Object successfully deleted from the source bucket: {delete_response.headers}")
        return {
            "action": "moved",
            "source_bucket": source_bucket,
            "target_bucket": target_bucket,
            "object_name": object_name,
            }
        
    except Exception as e:
        logger.error(f"Error moving file: {str(e)}")
       
        # Update source object with error information
        client.put_object(
            namespace_name=namespace,
            bucket_name=source_bucket,
            object_name=object_name,
            put_object_body=get_object_response.data.content,
            content_type=get_object_response.headers.get('content-type'),
            opc_meta={
                "copy-error": str(e)[:500],
                "error-timestamp": str(int(time.time()))
            }
        )
        
        logger.info("Error details added to source object")
        return {
            "action": "move_failed",
            "source_bucket": source_bucket,
            "target_bucket": target_bucket,
            "object_name": object_name,
            "error": str(e)
        }
