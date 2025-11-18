#!/usr/bin/env python3
"""
Test script for Vision One File Security Scanner function
This script validates the function logic without requiring full OCI deployment
"""

import io
import json
import os
import sys
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Add function directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'function'))

def create_test_event(bucket_name="v1-fss-source-bucket", object_name="test-file.txt"):
    """Create a test OCI event"""
    return {
        "eventType": "com.oraclecloud.objectstorage.object.create",
        "data": {
            "resourceName": object_name,
            "additionalDetails": {
                "bucketName": bucket_name,
                "namespace": "test-namespace"
            }
        }
    }

def test_event_parsing():
    """Test event parsing logic"""
    print("Testing event parsing...")
    
    # Import function after setting up path
    from func import handler
    
    # Test valid event
    test_event = create_test_event()
    test_data = io.BytesIO(json.dumps(test_event).encode())
    
    # Mock environment variables
    with patch.dict(os.environ, {
        'SOURCE_BUCKET_NAME': 'v1-fss-source-bucket',
        'PRODUCTION_BUCKET_NAME': 'v1-fss-prod-bucket',
        'QUARANTINE_BUCKET_NAME': 'v1-fss-quarantine-bucket',
        'VISION_ONE_API_KEY': 'test-api-key',
        'VISION_ONE_REGION': 'ap-southeast-2'
    }):
        # Mock OCI and Vision One components
        with patch('oci.auth.signers.get_resource_principals_signer'), \
             patch('oci.object_storage.ObjectStorageClient'), \
             patch('amaas.grpc.init_by_region'), \
             patch('amaas.grpc.scan_file') as mock_scan, \
             patch('amaas.grpc.quit'):
            
            # Mock scan result (clean file)
            mock_scan.return_value = json.dumps({
                "scanResult": 0,
                "foundMalwares": [],
                "scanId": "test-scan-id",
                "fileSHA256": "test-hash",
                "scannerVersion": "1.0.0"
            })
            
            # Mock file operations
            with patch('tempfile.NamedTemporaryFile'), \
                 patch('func.download_and_scan_file') as mock_download_scan, \
                 patch('func.move_file_based_on_scan') as mock_move:
                
                mock_download_scan.return_value = {
                    "is_malware_detected": False,
                    "scan_result_code": 0,
                    "found_malwares": [],
                    "scan_id": "test-scan-id"
                }
                
                mock_move.return_value = {
                    "action": "moved",
                    "target_bucket": "v1-fss-prod-bucket",
                    "is_malware_detected": False
                }
                
                result = handler(None, test_data)
                
                assert result["status"] == "success"
                print("✓ Event parsing test passed")

def test_malware_detection():
    """Test malware detection logic"""
    print("Testing malware detection...")
    
    from func import handler
    
    test_event = create_test_event(object_name="malware-test.exe")
    test_data = io.BytesIO(json.dumps(test_event).encode())
    
    with patch.dict(os.environ, {
        'SOURCE_BUCKET_NAME': 'v1-fss-source-bucket',
        'PRODUCTION_BUCKET_NAME': 'v1-fss-prod-bucket',
        'QUARANTINE_BUCKET_NAME': 'v1-fss-quarantine-bucket',
        'VISION_ONE_API_KEY': 'test-api-key',
        'VISION_ONE_REGION': 'ap-southeast-2'
    }):
        with patch('oci.auth.signers.get_resource_principals_signer'), \
             patch('oci.object_storage.ObjectStorageClient'), \
             patch('amaas.grpc.init_by_region'), \
             patch('amaas.grpc.scan_file') as mock_scan, \
             patch('amaas.grpc.quit'):
            
            # Mock scan result (malware detected)
            mock_scan.return_value = json.dumps({
                "scanResult": 1,
                "foundMalwares": [{"malwareName": "Test.Malware"}],
                "scanId": "test-scan-id-malware",
                "fileSHA256": "malware-hash",
                "scannerVersion": "1.0.0"
            })
            
            with patch('tempfile.NamedTemporaryFile'), \
                 patch('func.download_and_scan_file') as mock_download_scan, \
                 patch('func.move_file_based_on_scan') as mock_move:
                
                mock_download_scan.return_value = {
                    "is_malware_detected": True,
                    "scan_result_code": 1,
                    "found_malwares": [{"malwareName": "Test.Malware"}],
                    "scan_id": "test-scan-id-malware"
                }
                
                mock_move.return_value = {
                    "action": "moved",
                    "target_bucket": "v1-fss-quarantine-bucket",
                    "is_malware_detected": True
                }
                
                result = handler(None, test_data)
                
                assert result["status"] == "success"
                assert result["move_result"]["is_malware_detected"] == True
                print("✓ Malware detection test passed")

def test_configuration_validation():
    """Test configuration validation"""
    print("Testing configuration validation...")
    
    from func import get_configuration
    
    # Test missing environment variable
    with patch.dict(os.environ, {}, clear=True):
        try:
            get_configuration()
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Missing required environment variable" in str(e)
            print("✓ Configuration validation test passed")

def test_invalid_event():
    """Test handling of invalid events"""
    print("Testing invalid event handling...")
    
    from func import handler
    
    # Test non-PutObject event
    invalid_event = {
        "eventType": "com.oraclecloud.objectstorage.object.delete",
        "data": {
            "resourceName": "test-file.txt",
            "additionalDetails": {
                "bucketName": "v1-fss-source-bucket",
                "namespace": "test-namespace"
            }
        }
    }
    
    test_data = io.BytesIO(json.dumps(invalid_event).encode())
    
    with patch.dict(os.environ, {
        'SOURCE_BUCKET_NAME': 'v1-fss-source-bucket',
        'PRODUCTION_BUCKET_NAME': 'v1-fss-prod-bucket',
        'QUARANTINE_BUCKET_NAME': 'v1-fss-quarantine-bucket',
        'VISION_ONE_API_KEY': 'test-api-key',
        'VISION_ONE_REGION': 'ap-southeast-2'
    }):
        result = handler(None, test_data)
        
        assert result["status"] == "ignored"
        assert "Not a PutObject event" in result["reason"]
        print("✓ Invalid event handling test passed")

def test_wrong_bucket():
    """Test handling of files from wrong bucket"""
    print("Testing wrong bucket handling...")
    
    from func import handler
    
    # Test file from different bucket
    wrong_bucket_event = create_test_event(bucket_name="different-bucket")
    test_data = io.BytesIO(json.dumps(wrong_bucket_event).encode())
    
    with patch.dict(os.environ, {
        'SOURCE_BUCKET_NAME': 'v1-fss-source-bucket',
        'PRODUCTION_BUCKET_NAME': 'v1-fss-prod-bucket',
        'QUARANTINE_BUCKET_NAME': 'v1-fss-quarantine-bucket',
        'VISION_ONE_API_KEY': 'test-api-key',
        'VISION_ONE_REGION': 'ap-southeast-2'
    }):
        with patch('oci.auth.signers.get_resource_principals_signer'), \
             patch('oci.object_storage.ObjectStorageClient'):
            
            result = handler(None, test_data)
            
            assert result["status"] == "ignored"
            assert "Not from source bucket" in result["reason"]
            print("✓ Wrong bucket handling test passed")

def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Vision One File Security Scanner - Function Tests")
    print("=" * 60)
    
    tests = [
        test_configuration_validation,
        test_invalid_event,
        test_wrong_bucket,
        test_event_parsing,
        test_malware_detection
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("🎉 All tests passed! The function logic is working correctly.")
        return True
    else:
        print("❌ Some tests failed. Please review the function code.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
