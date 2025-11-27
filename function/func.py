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
    
    # Always required variables
    required_vars = [
        'SOURCE_BUCKET_NAME',
        'V1_REGION',
        'V1_SCANNER_ENDPOINT',
        'V1_FILE_SCANNER_MODE'
    ]
    
    # Vault-based variables (sensitive)
    vault_vars = [
        'VAULT_SECRET_OCID'
    ]
    
    config = {}
    
    # Get required configuration from environment variables
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            raise ValueError(f"Missing required environment variable: {var}")
        config[var.lower()] = value
    
    # Validate and set default for scanner mode
    scanner_mode = config.get('v1_file_scanner_mode', 'MOVE_ALL')
    valid_modes = ['MOVE_ALL', 'MOVE_MALWARE_ONLY', 'TAG_ONLY']
    
    if scanner_mode not in valid_modes:
        logger.warning(f"Invalid scanner mode '{scanner_mode}', falling back to 'MOVE_ALL'")
        config['v1_file_scanner_mode'] = 'MOVE_ALL'
        scanner_mode = 'MOVE_ALL'
    else:
        logger.info(f"Scanner mode set to: {scanner_mode}")
    
    # Get bucket configuration based on scanner mode
    if scanner_mode == 'MOVE_ALL':
        # Both production and quarantine buckets required
        for bucket_var in ['PRODUCTION_BUCKET_NAME', 'QUARANTINE_BUCKET_NAME']:
            value = os.environ.get(bucket_var)
            if not value:
                raise ValueError(f"Missing required environment variable for MOVE_ALL mode: {bucket_var}")
            config[bucket_var.lower()] = value
    
    elif scanner_mode == 'MOVE_MALWARE_ONLY':
        # Only quarantine bucket required
        value = os.environ.get('QUARANTINE_BUCKET_NAME')
        if not value:
            raise ValueError(f"Missing required environment variable for MOVE_MALWARE_ONLY mode: QUARANTINE_BUCKET_NAME")
        config['quarantine_bucket_name'] = value
        
        # Production bucket is optional
        prod_value = os.environ.get('PRODUCTION_BUCKET_NAME')
        if prod_value:
            config['production_bucket_name'] = prod_value
    
    elif scanner_mode == 'TAG_ONLY':
        # No additional buckets required, but get them if available for logging
        for bucket_var in ['PRODUCTION_BUCKET_NAME', 'QUARANTINE_BUCKET_NAME']:
            value = os.environ.get(bucket_var)
            if value:
                config[bucket_var.lower()] = value
    
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

def update_file_metadata_in_place(
    client: oci.object_storage.ObjectStorageClient,
    namespace: str,
    bucket_name: str,
    object_name: str,
    scan_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Update file metadata/tags in-place without moving the file"""
    
    try:
        # Get the original object content and details
        get_object_response = client.get_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=object_name
        )
        
        # Get existing metadata
        existing_meta = {}
        try:
            object_details = client.head_object(
                namespace_name=namespace,
                bucket_name=bucket_name,
                object_name=object_name
            )
            existing_meta = object_details.headers.get('opc-meta-data', {})
            if isinstance(existing_meta, str):
                existing_meta = json.loads(existing_meta)
        except:
            existing_meta = {}

        # Prepare scan result tags
        scan_tags = {
            "filescanned": "true",
            "ismalwaredetected": str(scan_result['is_malware_detected']).lower(),
            "scantimestamp": str(int(time.time())),
            "scanid": scan_result.get('scan_id', ''),
            "scannerversion": scan_result.get('scanner_version', '')
        }

        if scan_result['is_malware_detected']:
            malware_names = ",".join([m.get('malwareName', '') for m in scan_result.get('found_malwares', [])])
            scan_tags["malwarenames"] = malware_names[:200]  # Limit tag value

        # Merge existing metadata with scan tags
        updated_meta = {**existing_meta, **scan_tags}
        
        # Update the object in-place with new metadata
        logger.info(f"Updating metadata for object {object_name} in bucket {bucket_name}")
        
        copy_response = client.put_object(
            namespace_name=namespace,
            bucket_name=bucket_name,
            object_name=object_name,
            put_object_body=get_object_response.data.content,
            content_type=get_object_response.headers.get('content-type'),
            opc_meta=updated_meta
        )
        
        logger.info(f"Metadata successfully updated for object in {bucket_name}")
        
        return {
            "action": "metadata_updated",
            "bucket": bucket_name,
            "object_name": object_name,
            "scan_tags_added": scan_tags
        }
        
    except Exception as e:
        logger.error(f"Error updating metadata: {str(e)}")
        return {
            "action": "metadata_update_failed",
            "bucket": bucket_name,
            "object_name": object_name,
            "error": str(e)
        }

def move_file_based_on_scan(
    client: oci.object_storage.ObjectStorageClient,
    namespace: str,
    source_bucket: str,
    object_name: str,
    scan_result: Dict[str, Any],
    config: Dict[str, str]
) -> Dict[str, Any]:
    """
    Process file based on scan results and configured scanner mode.
    
    Modes:
    - MOVE_ALL: Move both clean and infected files to appropriate buckets
    - MOVE_MALWARE_ONLY: Only move infected files to quarantine, tag clean files in-place
    - TAG_ONLY: Tag all files in-place without moving
    """
    
    is_malware_detected = scan_result['is_malware_detected']
    scanner_mode = config.get('v1_file_scanner_mode', 'MOVE_ALL')
    
    logger.info(f"Processing file with scanner mode: {scanner_mode}")
    logger.info(f"Malware detected: {is_malware_detected}")
    
    # MODE 1: TAG_ONLY - Always tag files in-place, never move
    if scanner_mode == 'TAG_ONLY':
        logger.info("TAG_ONLY mode: Updating file metadata in-place")
        return update_file_metadata_in_place(
            client, namespace, source_bucket, object_name, scan_result
        )
    
    # MODE 2: MOVE_MALWARE_ONLY - Move only malware to quarantine, tag clean files in-place
    elif scanner_mode == 'MOVE_MALWARE_ONLY':
        if is_malware_detected:
            logger.info("MOVE_MALWARE_ONLY mode: Moving infected file to quarantine")
            return move_file_to_bucket(
                client, namespace, source_bucket, object_name, 
                config['quarantine_bucket_name'], scan_result, config
            )
        else:
            logger.info("MOVE_MALWARE_ONLY mode: Clean file detected, updating metadata in-place")
            return update_file_metadata_in_place(
                client, namespace, source_bucket, object_name, scan_result
            )
    
    # MODE 3: MOVE_ALL - Move all files to appropriate buckets (original behavior)
    else:  # MOVE_ALL or any other value falls back to this mode
        target_bucket = config['quarantine_bucket_name'] if is_malware_detected else config['production_bucket_name']
        logger.info(f"MOVE_ALL mode: Moving file to {'quarantine' if is_malware_detected else 'production'} bucket: {target_bucket}")
        return move_file_to_bucket(
            client, namespace, source_bucket, object_name, 
            target_bucket, scan_result, config
        )

def move_file_to_bucket(
    client: oci.object_storage.ObjectStorageClient,
    namespace: str,
    source_bucket: str,
    object_name: str,
    target_bucket: str,
    scan_result: Dict[str, Any],
    config: Dict[str, str]
) -> Dict[str, Any]:
    """Move file from source bucket to target bucket with scan metadata"""
    
    try:
        # Get the original object
        get_object_response = client.get_object(
            namespace_name=namespace,
            bucket_name=source_bucket,
            object_name=object_name
        )
        
        # Get existing metadata from source object
        existing_meta = {}
        try:
            object_details = client.head_object(
                namespace_name=namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            existing_meta = object_details.headers.get('opc-meta-data', {})
            if isinstance(existing_meta, str):
                existing_meta = json.loads(existing_meta)
        except:
            existing_meta = {}

        # Prepare scan result tags
        scan_tags = {
            "filescanned": "true",
            "ismalwaredetected": str(scan_result['is_malware_detected']).lower(),
            "scantimestamp": str(int(time.time())),
            "scanid": scan_result.get('scan_id', ''),
            "scannerversion": scan_result.get('scanner_version', ''),
            "originalbucket": source_bucket
        }

        if scan_result['is_malware_detected']:
            malware_names = ",".join([m.get('malwareName', '') for m in scan_result.get('found_malwares', [])])
            scan_tags["malwarenames"] = malware_names[:200]  # Limit tag value

        # Merge existing metadata with scan tags
        updated_meta = {**existing_meta, **scan_tags}
   
        try:
            # Copy object to target bucket with updated metadata
            logger.info(f"Copying object from {source_bucket} to {target_bucket}")
            
            copy_response = client.put_object(
                namespace_name=namespace,
                bucket_name=target_bucket,
                object_name=object_name,
                put_object_body=get_object_response.data.content,
                content_type=get_object_response.headers.get('content-type'),
                opc_meta=updated_meta
            )
            
            logger.info(f"Object successfully copied to target bucket: {target_bucket}")
           
        except Exception as copy_error:
            logger.error(f"Error copying object: {str(copy_error)}")

            # Update source object with error information
            error_meta = {**existing_meta, **{
                "copy-error": str(copy_error)[:500],
                "error-timestamp": str(int(time.time()))
            }}
            
            client.put_object(
                namespace_name=namespace,
                bucket_name=source_bucket,
                object_name=object_name,
                put_object_body=get_object_response.data.content,
                content_type=get_object_response.headers.get('content-type'),
                opc_meta=error_meta
            )
            
            logger.info("Error details added to source object")
            return {
                "action": "copy_failed",
                "source_bucket": source_bucket,
                "target_bucket": target_bucket,
                "object_name": object_name,
                "error": str(copy_error)
            }
        
        # Delete the object from the source bucket after successful copy
        logger.info(f"Deleting object from source bucket: {source_bucket}")
        delete_response = client.delete_object(
            namespace_name=namespace,
            bucket_name=source_bucket,
            object_name=object_name
        )
        logger.info(f"Object successfully deleted from source bucket")
        
        return {
            "action": "moved",
            "source_bucket": source_bucket,
            "target_bucket": target_bucket,
            "object_name": object_name,
            "scan_tags_added": scan_tags
        }
        
    except Exception as e:
        logger.error(f"Error moving file: {str(e)}")
       
        try:
            # Update source object with error information
            error_meta = {
                "move-error": str(e)[:500],
                "error-timestamp": str(int(time.time()))
            }
            
            # Get existing content to preserve it
            get_object_response = client.get_object(
                namespace_name=namespace,
                bucket_name=source_bucket,
                object_name=object_name
            )
            
            client.put_object(
                namespace_name=namespace,
                bucket_name=source_bucket,
                object_name=object_name,
                put_object_body=get_object_response.data.content,
                content_type=get_object_response.headers.get('content-type'),
                opc_meta=error_meta
            )
            
            logger.info("Error details added to source object")
        except Exception as error_update_exception:
            logger.error(f"Failed to update source object with error details: {str(error_update_exception)}")
        
        return {
            "action": "move_failed",
            "source_bucket": source_bucket,
            "target_bucket": target_bucket,
            "object_name": object_name,
            "error": str(e)
        }
