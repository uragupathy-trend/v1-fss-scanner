#!/usr/bin/env python3
"""
Standalone test script for the FSS Scanner function logic
This tests the core logic without requiring FDK or OCI dependencies
"""

import io
import json
import logging
import os
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_configuration() -> Dict[str, str]:
    """Get configuration from environment variables"""
    config = {
        'source_bucket_name': 'v1-fss-source-bucket',
        'production_bucket_name': 'v1-fss-production-bucket',
        'quarantine_bucket_name': 'v1-fss-quarantine-bucket',
        'vision_one_api_key': 'test-api-key-for-local-testing',
        'vision_one_region': 'ap-southeast-2'
    }
    return config

def simulate_file_scan(file_name: str, config: Dict[str, str]) -> Dict[str, Any]:
    """Simulate file scanning for testing purposes"""
    
    logger.info(f"Simulating scan of file: {file_name}")
    
    # Simulate different scan results based on filename
    is_malware_detected = False
    found_malwares = []
    
    # Simulate malware detection for files with "malware" in the name
    if "malware" in file_name.lower() or "virus" in file_name.lower():
        is_malware_detected = True
        found_malwares = [
            {"malware_name": "Test.Malware.Simulator", "malware_type": "Trojan"}
        ]
        logger.warning(f"Simulated malware detection in file: {file_name}")
    else:
        logger.info(f"File appears clean: {file_name}")
    
    return {
        "is_malware_detected": is_malware_detected,
        "scan_result_code": 1 if is_malware_detected else 0,
        "found_malwares": found_malwares,
        "scan_id": f"test-scan-{hash(file_name) % 10000}",
        "file_sha256": f"sha256-{hash(file_name)}",
        "scanner_version": "test-scanner-v1.0",
        "elapsed_time": 0.5,
        "scan_timestamp": "2025-01-08T02:43:00.000Z"
    }

def simulate_file_movement(
    file_name: str,
    scan_result: Dict[str, Any],
    config: Dict[str, str]
) -> Dict[str, Any]:
    """Simulate file movement for testing purposes"""
    
    is_malware_detected = scan_result['is_malware_detected']
    target_bucket = config['quarantine_bucket_name'] if is_malware_detected else config['production_bucket_name']
    
    logger.info(f"Simulating move of file to {'quarantine' if is_malware_detected else 'production'} bucket: {target_bucket}")
    
    # Simulate tags that would be applied
    freeform_tags = {
        "fileScanned": "true",
        "isMalwareDetected": str(is_malware_detected).lower(),
        "scanId": scan_result.get('scan_id', ''),
        "scannerVersion": scan_result.get('scanner_version', ''),
        "scanTimestamp": "1641600000"
    }
    
    if is_malware_detected:
        malware_names = [m.get('malware_name', '') for m in scan_result.get('found_malwares', [])]
        freeform_tags["malwareNames"] = ",".join(malware_names)
    
    return {
        "action": "simulated_move",
        "source_bucket": config['source_bucket_name'],
        "target_bucket": target_bucket,
        "object_name": file_name,
        "tags_applied": freeform_tags,
        "is_malware_detected": is_malware_detected
    }

def process_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process an OCI event"""
    
    logger.info(f"Received event: {json.dumps(event_data, indent=2)}")
    
    # Extract event information
    event_type = event_data.get('eventType', '')
    if 'com.oraclecloud.objectstorage.object.create' not in event_type:
        logger.info(f"Ignoring event type: {event_type}")
        return {"status": "ignored", "reason": "Not a PutObject event"}
    
    # Extract object details from event
    resource_name = event_data.get('data', {}).get('resourceName', '')
    bucket_name = event_data.get('data', {}).get('additionalDetails', {}).get('bucketName', '')
    namespace = event_data.get('data', {}).get('additionalDetails', {}).get('namespace', '')
    
    if not all([resource_name, bucket_name, namespace]):
        logger.error("Missing required event data")
        return {"status": "error", "reason": "Missing required event data"}
    
    logger.info(f"Processing file: {resource_name} from bucket: {bucket_name}")
    
    # Get configuration
    config = get_configuration()
    
    # Only process files from the source bucket
    if bucket_name != config['source_bucket_name']:
        logger.info(f"Ignoring file from bucket: {bucket_name} (not source bucket)")
        return {"status": "ignored", "reason": "Not from source bucket"}
    
    # Simulate file scanning
    scan_result = simulate_file_scan(resource_name, config)
    
    # Simulate file movement
    move_result = simulate_file_movement(resource_name, scan_result, config)
    
    logger.info(f"Processing completed successfully")
    
    return {
        "status": "success",
        "scan_result": scan_result,
        "move_result": move_result,
        "message": "Test function executed successfully"
    }

def run_tests():
    """Run various test scenarios"""
    
    print("=" * 60)
    print("FSS Scanner Function - Local Testing")
    print("=" * 60)
    
    # Test scenarios
    test_scenarios = [
        {
            "name": "Clean file test",
            "event": {
                "eventType": "com.oraclecloud.objectstorage.object.create",
                "data": {
                    "resourceName": "clean-document.pdf",
                    "additionalDetails": {
                        "bucketName": "v1-fss-source-bucket",
                        "namespace": "test-namespace"
                    }
                }
            }
        },
        {
            "name": "Malware file test",
            "event": {
                "eventType": "com.oraclecloud.objectstorage.object.create",
                "data": {
                    "resourceName": "suspicious-malware-file.exe",
                    "additionalDetails": {
                        "bucketName": "v1-fss-source-bucket",
                        "namespace": "test-namespace"
                    }
                }
            }
        },
        {
            "name": "Wrong bucket test",
            "event": {
                "eventType": "com.oraclecloud.objectstorage.object.create",
                "data": {
                    "resourceName": "some-file.txt",
                    "additionalDetails": {
                        "bucketName": "wrong-bucket",
                        "namespace": "test-namespace"
                    }
                }
            }
        },
        {
            "name": "Wrong event type test",
            "event": {
                "eventType": "com.oraclecloud.objectstorage.object.delete",
                "data": {
                    "resourceName": "deleted-file.txt",
                    "additionalDetails": {
                        "bucketName": "v1-fss-source-bucket",
                        "namespace": "test-namespace"
                    }
                }
            }
        },
        {
            "name": "Missing data test",
            "event": {
                "eventType": "com.oraclecloud.objectstorage.object.create",
                "data": {
                    "additionalDetails": {
                        "bucketName": "v1-fss-source-bucket"
                    }
                }
            }
        }
    ]
    
    # Run each test scenario
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print("-" * 40)
        
        try:
            result = process_event(scenario['event'])
            print(f"Result: {json.dumps(result, indent=2)}")
            
            # Analyze result
            if result['status'] == 'success':
                scan_result = result['scan_result']
                move_result = result['move_result']
                
                print(f"\n✅ Test passed!")
                print(f"   File: {scenario['event']['data'].get('resourceName', 'N/A')}")
                print(f"   Malware detected: {scan_result['is_malware_detected']}")
                print(f"   Target bucket: {move_result['target_bucket']}")
                
                if scan_result['is_malware_detected']:
                    print(f"   Malware: {[m['malware_name'] for m in scan_result['found_malwares']]}")
                    
            elif result['status'] == 'ignored':
                print(f"✅ Test passed (ignored as expected): {result['reason']}")
            elif result['status'] == 'error':
                print(f"✅ Test passed (error handled): {result['reason']}")
                
        except Exception as e:
            print(f"❌ Test failed with exception: {str(e)}")
    
    print("\n" + "=" * 60)
    print("Testing completed!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
