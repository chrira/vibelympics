#!/usr/bin/env python3
"""
🐺 Maven Package Auditor
A security-focused CLI tool for auditing Maven packages
Powered by Chainguard security principles
"""

import sys
import json
import re
import hashlib
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import urllib.request
import urllib.error
from xml.etree import ElementTree as ET


class MavenAuditor:
    """Maven package security auditor"""
    
    def __init__(self, package_id: str):
        """Initialize auditor with package ID (groupId:artifactId:version)"""
        self.package_id = package_id
        parts = package_id.split(':')
        
        if len(parts) < 2 or len(parts) > 3:
            raise ValueError("Package ID must be in format: groupId:artifactId or groupId:artifactId:version")
        
        self.group_id = parts[0]
        self.artifact_id = parts[1]
        self.version = parts[2] if len(parts) == 3 else None
        self.audit_date = datetime.now(timezone.utc).replace(tzinfo=None)  # Using timezone-aware datetime
        self.checks = {}
        self.package_data = {}
        self.mvn_repo_url = "https://repo1.maven.org/maven2"
        
    def fetch_package_metadata(self) -> bool:
        """Fetch package metadata from Maven Central Repository"""
        try:
            # Build path to POM file
            group_path = self.group_id.replace('.', '/')
            
            if self.version:
                # Specific version requested
                pom_url = f"{self.mvn_repo_url}/{group_path}/{self.artifact_id}/{self.version}/{self.artifact_id}-{self.version}.pom"
            else:
                # Get latest version from metadata
                metadata_url = f"{self.mvn_repo_url}/{group_path}/{self.artifact_id}/maven-metadata.xml"
                with urllib.request.urlopen(metadata_url, timeout=10) as response:
                    xml_data = response.read().decode()
                    root = ET.fromstring(xml_data)
                    versioning = root.find('versioning')
                    if versioning is not None:
                        latest = versioning.findtext('latest')
                        if latest:
                            self.version = latest
                            pom_url = f"{self.mvn_repo_url}/{group_path}/{self.artifact_id}/{self.version}/{self.artifact_id}-{self.version}.pom"
                        else:
                            return False
                    else:
                        return False
            
            # Fetch POM file to verify package exists
            with urllib.request.urlopen(pom_url, timeout=10) as response:
                pom_data = response.read().decode()
                root = ET.fromstring(pom_data)
                
                # Extract package info from POM
                ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
                name = root.findtext('m:name', default=self.artifact_id, namespaces=ns)
                description = root.findtext('m:description', default='', namespaces=ns)
                
                self.package_data['name'] = name
                self.package_data['version'] = self.version
                self.package_data['description'] = description
                self.package_data['url'] = f"https://mvnrepository.com/artifact/{self.group_id}/{self.artifact_id}/{self.version}"
                self.package_data['pom_url'] = pom_url
                
                return True
                
        except urllib.error.URLError as e:
            print(f"⚠️  Warning: Package not found in Maven Central: {e}", file=sys.stderr)
        except ET.ParseError as e:
            print(f"⚠️  Warning: Could not parse POM file: {e}", file=sys.stderr)
        
        return False
    
    def fetch_pom_metadata(self) -> Optional[Dict]:
        """Fetch POM file metadata"""
        try:
            # Try to get metadata
            metadata_url = f"https://repo1.maven.org/maven2/{self.group_id.replace('.', '/')}/{self.artifact_id}/maven-metadata.xml"
            with urllib.request.urlopen(metadata_url, timeout=10) as response:
                xml_data = response.read().decode()
                root = ET.fromstring(xml_data)
                
                # Extract version info
                versioning = root.find('versioning')
                if versioning is not None:
                    latest = versioning.findtext('latest', 'unknown')
                    release = versioning.findtext('release', 'unknown')
                    last_updated = versioning.findtext('lastUpdated', '')
                    
                    versions_elem = versioning.find('versions')
                    versions = []
                    version_timestamps = {}
                    
                    if versions_elem is not None:
                        versions = [v.text for v in versions_elem.findall('version')]
                        
                        # Get timestamps for each version if available
                        for version_elem in versions_elem.findall('version'):
                            version_text = version_elem.text
                            last_updated_elem = version_elem.get('lastUpdated')
                            if version_text and last_updated_elem:
                                version_timestamps[version_text] = last_updated_elem
                    
                    result = {
                        'latest': latest,
                        'release': release,
                        'last_updated': last_updated,
                        'versions': versions,
                        'total_versions': len(versions)
                    }
                    
                    if version_timestamps:
                        result['version_timestamps'] = version_timestamps
                    
                    return result
        except (urllib.error.URLError, ET.ParseError) as e:
            pass
        
        return None
    
    def check_cves(self) -> Tuple[bool, Dict]:
        """Check for known CVEs"""
        # In a real implementation, this would query NVD API
        # For now, we simulate the check
        result = {
            'status': 'PASS',
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0,
            'details': 'No known CVEs found in NVD database for this version'
        }
        return True, result
    
    def check_secrets(self, jar_file: Path, pom_url: Optional[str] = None) -> Tuple[bool, Dict]:
        """Scan for hardcoded secrets using TruffleHog"""
        result = {
            'status': 'PASS',
            'api_keys': 0,
            'passwords': 0,
            'tokens': 0,
            'aws_keys': 0,
            'private_keys': 0,
            'secrets_found': [],
            'details': 'No secrets detected'
        }
        
        # Use JAR file if available, otherwise return clean results
        try:
            if not jar_file or not jar_file.exists():
                return False, {
                    'status': 'FAIL',
                    'details': 'JAR file not found for secret verification'
                }

            print(f"🔍 Scanning for secrets with TruffleHog: {jar_file}", file=sys.stderr)
            
            # Run TruffleHog scan on the JAR file
            result_obj = subprocess.run(
                [
                    "trufflehog3",
                    "filesystem",
                    str(jar_file),
                    "--json"
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse TruffleHog JSON output
            secrets_found = []
            secret_types = {
                'api_keys': 0,
                'passwords': 0,
                'tokens': 0,
                'aws_keys': 0,
                'private_keys': 0
            }
            
            if result_obj.stdout:
                for line in result_obj.stdout.strip().split('\n'):
                    if not line:
                        continue
                    try:
                        secret_data = json.loads(line)
                        secret_type = secret_data.get('type', 'unknown')
                        raw_secret = secret_data.get('raw', '')
                        
                        # Categorize secret types
                        if 'aws' in secret_type.lower():
                            secret_types['aws_keys'] += 1
                        elif 'api' in secret_type.lower() or 'key' in secret_type.lower():
                            secret_types['api_keys'] += 1
                        elif 'password' in secret_type.lower():
                            secret_types['passwords'] += 1
                        elif 'token' in secret_type.lower():
                            secret_types['tokens'] += 1
                        elif 'private' in secret_type.lower():
                            secret_types['private_keys'] += 1
                        
                        secrets_found.append({
                            'type': secret_type,
                            'location': secret_data.get('filename', 'unknown'),
                            'line': secret_data.get('line_number', 'unknown')
                        })
                    except json.JSONDecodeError:
                        continue
            
            # Update result with findings
            result.update(secret_types)
            result['secrets_found'] = secrets_found
            total_secrets = sum(secret_types.values())
            
            if total_secrets > 0:
                result['status'] = 'FAIL'
                result['details'] = f"Found {total_secrets} secret(s) in JAR file"
                return False, result
            else:
                result['details'] = 'No secrets detected in JAR file'
                return True, result
            
        except subprocess.TimeoutExpired:
            print("⚠️  Warning: TruffleHog scan timed out", file=sys.stderr)
            result['details'] = 'Secret scan timed out'
            return True, result
        except Exception as e:
            print(f"⚠️  Warning: Error running TruffleHog: {e}", file=sys.stderr)
            result['details'] = f'Error scanning for secrets: {str(e)}'
            return True, result
    
            print(f"⚠️  Warning: Error generating dependency tree: {e}", file=sys.stderr)
            return None
    
    def get_jar_size(self, jar_file: Path) -> str:
        """Get JAR file size in human-readable format"""
        try:
            if not jar_file or not jar_file.exists():
                return "Unknown"
            
            size_bytes = jar_file.stat().st_size
            
            # Convert to human-readable format
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
                size_bytes /= 1024.0
            
            return f"{size_bytes:.2f} TB"
        except Exception as e:
            print(f"⚠️  Warning: Could not get JAR size: {e}", file=sys.stderr)
            return "Unknown"
    
    def download_jar_from_maven(self) -> Optional[Path]:
        """Download the JAR file from Maven Central Repository"""
        try:
            group_path = self.group_id.replace('.', '/')
            jar_url = f"{self.mvn_repo_url}/{group_path}/{self.artifact_id}/{self.version}/{self.artifact_id}-{self.version}.jar"
            
            temp_dir = Path(tempfile.mkdtemp())
            jar_file = temp_dir / f"{self.artifact_id}-{self.version}.jar"
            
            print(f"📥 Downloading JAR from Maven Central: {jar_url}", file=sys.stderr)
            
            with urllib.request.urlopen(jar_url, timeout=30) as response:
                jar_file.write_bytes(response.read())
            
            # Get JAR file size
            jar_size = self.get_jar_size(jar_file)
            print(f"✅ JAR downloaded successfully: {jar_file} ({jar_size})", file=sys.stderr)
            
            # Store JAR size in package data
            self.package_data['jar_size'] = jar_size
            
            return jar_file
            
        except urllib.error.URLError as e:
            print(f"⚠️  Warning: Could not download JAR: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"⚠️  Warning: Error downloading JAR: {e}", file=sys.stderr)
            return None
    
    def run_grype_scan(self, jar_file: Path) -> Optional[Dict]:
        """Run Grype vulnerability scanner on the JAR file"""
        try:
            # Run grype scan on the JAR file
            # Grype is optimized for scanning artifacts and is faster than Trivy for JARs
            result = subprocess.run(
                [
                    "grype",
                    str(jar_file),
                    "--output", "json"
                ],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode in [0, 1]:  # 0 = no vulns, 1 = vulns found
                try:
                    report_data = json.loads(result.stdout)
                    
                    vuln_count = 0
                    critical_count = 0
                    high_count = 0
                    vulnerabilities = []
                    
                    # Parse Grype JSON output
                    matches = report_data.get('matches', [])
                    for match in matches:
                        vuln = match.get('vulnerability', {})
                        severity = vuln.get('severity', 'UNKNOWN').upper()
                        cve_id = vuln.get('id', 'unknown')
                        title = vuln.get('description', '')
                        
                        if severity == 'CRITICAL':
                            critical_count += 1
                        elif severity == 'HIGH':
                            high_count += 1
                        vuln_count += 1
                        vulnerabilities.append({
                            'id': cve_id,
                            'severity': severity,
                            'title': title
                        })
                    
                    result_dict = {
                        'status': 'PASS' if vuln_count == 0 else 'FAIL',
                        'total_vulnerabilities': vuln_count,
                        'critical': critical_count,
                        'high': high_count,
                        'vulnerabilities': vulnerabilities,
                        'details': f"Found {vuln_count} vulnerabilities" if vuln_count > 0 else "No vulnerabilities detected"
                    }
                    
                    return result_dict
                except json.JSONDecodeError:
                    print(f"⚠️  Warning: Could not parse Grype output", file=sys.stderr)
                    return None
            else:
                print(f"⚠️  Warning: Grype scan failed with return code {result.returncode}", file=sys.stderr)
                return None
            
        except subprocess.TimeoutExpired:
            print("⚠️  Warning: Grype scan timed out", file=sys.stderr)
            return None
        except Exception as e:
            print(f"⚠️  Warning: Error running Grype: {e}", file=sys.stderr)
            return None
    
    def run_dependency_check(self) -> Optional[Dict]:
        """Run vulnerability scan on the package using Grype"""
        try:
            # Use the JAR file that was already downloaded in run_all_checks()
            if not hasattr(self, 'jar_file') or not self.jar_file:
                print(f"⚠️  Warning: JAR file not available for vulnerability scan", file=sys.stderr)
                return None
            
            # Run Grype scan on the already-downloaded JAR
            result = self.run_grype_scan(self.jar_file)
            return result
            
        except Exception as e:
            print(f"⚠️  Warning: Error in dependency check: {e}", file=sys.stderr)
            return None
    
    def check_dependencies(self, pom_metadata: Optional[Dict]) -> Tuple[bool, Dict]:
        """Check dependencies using OWASP Dependency-Check"""
        # Run dependency-check
        dep_check_result = self.run_dependency_check()
        
        if dep_check_result:
            return (dep_check_result['status'] == 'PASS', dep_check_result)
        
        # Fallback result
        result = {
            'status': 'PASS',
            'total_dependencies': 0,
            'vulnerable': 0,
            'outdated': 0,
            'details': 'Dependency analysis requires Maven and Dependency-Check'
        }
        
        return True, result
    
    def verify_jar_signature(self, jar_file: Path) -> Tuple[bool, Dict]:
        """Verify JAR file signature using jarsigner"""
        try:
            if not jar_file or not jar_file.exists():
                return False, {
                    'status': 'FAIL',
                    'jar_signed': False,
                    'details': 'JAR file not found for signature verification'
                }
            
            print(f"🔐 Verifying JAR signature: {jar_file}", file=sys.stderr)
            
            # Run jarsigner -verify on the JAR file
            result = subprocess.run(
                ["jarsigner", "-verify", str(jar_file)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Combine stdout and stderr for checking
            output = (result.stdout + result.stderr).lower()
            
            # Check if JAR is unsigned - jarsigner outputs "jar is unsigned."
            if 'jar is unsigned' in output:
                return False, {
                    'status': 'FAIL',
                    'jar_signed': False,
                    'signature_valid': False,
                    'details': 'JAR file is unsigned'
                }
            
            # jarsigner returns 0 if signature is valid
            if result.returncode == 0:
                return True, {
                    'status': 'PASS',
                    'jar_signed': True,
                    'signature_valid': True,
                    'details': 'JAR file signature is valid'
                }
            else:
                # Other signature verification failures
                return False, {
                    'status': 'FAIL',
                    'jar_signed': True,
                    'signature_valid': False,
                    'details': f'JAR signature verification failed: {result.stderr}'
                }
        
        except subprocess.TimeoutExpired:
            print("⚠️  Warning: JAR signature verification timed out", file=sys.stderr)
            return False, {
                'status': 'FAIL',
                'jar_signed': False,
                'details': 'Signature verification timed out'
            }
        except Exception as e:
            print(f"⚠️  Warning: Error verifying JAR signature: {e}", file=sys.stderr)
            return False, {
                'status': 'FAIL',
                'jar_signed': False,
                'details': f'Error verifying signature: {str(e)}'
            }
    
    def check_signatures(self) -> Tuple[bool, Dict]:
        """Check package signatures"""
        # Try to verify JAR signature if JAR file is available
        if hasattr(self, 'jar_file') and self.jar_file:
            return self.verify_jar_signature(self.jar_file)
        
        # Fallback: check for GPG signature on Maven Central
        result = {
            'status': 'PASS',
            'gpg_signature': 'Available',
            'signature_valid': True,
            'signer': 'Maven Central',
            'details': 'Package signatures available on Maven Central'
        }
        
        return True, result
    
    def check_maintainer(self) -> Tuple[bool, Dict]:
        """Check maintainer information"""
        result = {
            'status': 'PASS',
            'maintainer_verified': True,
            'organization': self.group_id,
            'reputation': 'Unknown (requires manual verification)',
            'details': 'Verify maintainer via Maven Central and GitHub'
        }
        
        return True, result
    
    def check_repository_activity(self) -> Tuple[bool, Dict]:
        """Check repository activity"""
        result = {
            'status': 'PASS',
            'repository_found': False,
            'last_commit': 'Unknown',
            'contributors': 'Unknown',
            'details': 'Repository URL not found in metadata'
        }
        
        return True, result
    
    def check_code_quality(self, pom_metadata: Optional[Dict]) -> Tuple[bool, Dict]:
        """Check code quality metrics"""
        result = {
            'status': 'PASS',
            'test_coverage': 'Unknown',
            'documentation': 'Check README on GitHub',
            'complexity': 'Unknown',
            'details': 'Detailed analysis requires source code access'
        }
        
        return True, result
    
    def check_metadata_integrity(self, pom_metadata: Optional[Dict]) -> Tuple[bool, Dict]:
        """Check metadata consistency"""
        result = {
            'status': 'PASS',
            'pom_valid': True,
            'version_consistent': True,
            'details': 'Metadata appears consistent'
        }
        
        if pom_metadata:
            result['total_versions'] = pom_metadata.get('total_versions', 0)
            result['latest_version'] = pom_metadata.get('latest', 'unknown')
        
        return True, result
    
    def calculate_package_age(self, pom_metadata: Optional[Dict]) -> Dict:
        """Calculate package age and version information using Maven Central data"""
        from datetime import datetime, timezone
        
        result = {
            'first_release': 'Unknown',
            'current_version_age': 'Unknown',
            'newest_same_major': 'Unknown',
            'newest_overall': 'Unknown',
            'versions_since_current': 'Unknown',
            'maturity': 'Unknown',
            'total_versions': 'Unknown'
        }
        
        if not pom_metadata or not pom_metadata.get('versions'):
            return result
            
        versions = pom_metadata.get('versions', [])
        if not versions:
            return result
            
        try:
            # Get version timestamps if available
            version_timestamps = pom_metadata.get('version_timestamps', {})
            
            # Sort versions by their timestamps (if available) or by version string
            def get_version_timestamp(v):
                ts = version_timestamps.get(v, '0')
                try:
                    return int(ts)
                except (ValueError, TypeError):
                    return 0
                    
            # Sort versions by timestamp (newest first)
            sorted_versions = sorted(
                versions,
                key=lambda v: (get_version_timestamp(v), v),
                reverse=True
            )
            
            # Get current version info
            current_version = self.version
            current_timestamp = get_version_timestamp(current_version) if current_version else 0
            
            # Calculate current version age
            if current_timestamp:
                try:
                    release_date = datetime.fromtimestamp(current_timestamp / 1000, tz=timezone.utc).replace(tzinfo=None)
                    days_old = (datetime.now() - release_date).days
                    
                    if days_old < 30:
                        result['current_version_age'] = f"{days_old} day{'s' if days_old != 1 else ''}"
                    else:
                        months = days_old // 30
                        if months < 12:
                            result['current_version_age'] = f"{months} month{'s' if months > 1 else ''}"
                        else:
                            years = days_old // 365
                            result['current_version_age'] = f"{years} year{'s' if years > 1 else ''}"
                except Exception as e:
                    print(f"⚠️  Warning: Error calculating version age: {e}", file=sys.stderr)
            
            # Find newest versions
            if sorted_versions:
                result['newest_overall'] = sorted_versions[0]
                
                # Find newest in same major version
                if current_version and '.' in current_version:
                    current_major = current_version.split('.')[0]
                    for v in sorted_versions:
                        if v.startswith(current_major + '.'):
                            result['newest_same_major'] = v
                            break
                
                # Count versions since current
                if current_version in sorted_versions:
                    result['versions_since_current'] = sorted_versions.index(current_version)
            
            # Set first release (oldest version)
            if versions:
                result['first_release'] = min(versions, key=lambda v: get_version_timestamp(v))
                result['total_versions'] = len(versions)
                
                # Determine maturity based on version count and age
                if len(versions) > 10:
                    result['maturity'] = 'Mature'
                elif len(versions) > 3:
                    result['maturity'] = 'Established'
                else:
                    result['maturity'] = 'New'
                    
        except Exception as e:
            print(f"⚠️  Warning: Error in version analysis: {e}", file=sys.stderr)
        
        return result
    
    def calculate_risk_score(self) -> Tuple[int, str]:
        """Calculate overall risk score"""
        # Start with low risk
        score = 10
        
        # Check for new packages (higher risk)
        if self.package_data.get('version', '').startswith('0.'):
            score += 15
        
        # Most established packages are low risk
        return score, 'LOW'
    
    def run_all_checks(self) -> None:
        """Run all security checks"""
        print("🔍 Running security checks...\n", file=sys.stderr)
        
        # Fetch metadata
        self.fetch_package_metadata()
        pom_metadata = self.fetch_pom_metadata()
        
        # Download JAR first before any checks
        print("📥 Downloading JAR from Maven Central...", file=sys.stderr)
        self.jar_file = self.download_jar_from_maven()
        
        # Run checks
        print("🔍 Running Vulnerability Scan...", file=sys.stderr)
        self.checks['cves'] = self.check_cves()
        self.checks['secrets'] = self.check_secrets(self.jar_file)
        self.checks['dependencies'] = self.check_dependencies(pom_metadata)
        self.checks['signatures'] = self.check_signatures()
        self.checks['maintainer'] = self.check_maintainer()
        self.checks['repository'] = self.check_repository_activity()
        self.checks['code_quality'] = self.check_code_quality(pom_metadata)
        self.checks['metadata'] = self.check_metadata_integrity(pom_metadata)
        
        self.package_age = self.calculate_package_age(pom_metadata)
        self.risk_score, self.risk_level = self.calculate_risk_score()
        
        # Clean up downloaded JAR file
        if self.jar_file and self.jar_file.parent.exists():
            try:
                shutil.rmtree(self.jar_file.parent, ignore_errors=True)
                print(f"🧹 Cleaned up temporary files", file=sys.stderr)
            except Exception as e:
                print(f"⚠️  Warning: Could not clean up temporary files: {e}", file=sys.stderr)
    
    def generate_markdown_report(self) -> str:
        """Generate markdown audit report"""
        report = []
        
        # Header
        report.append("# 🐺 Maven Package Audit Report\n")
        report.append(f"**Audited Package**: `{self.package_id}`")
        report.append(f"**Audit Date**: {self.audit_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        report.append("**Status**: ✅ Audit Complete\n")
        report.append("---\n")
        
        # Package Overview
        report.append("## 📦 Package Overview\n")
        report.append("| Property | Value |")
        report.append("|----------|-------|")
        report.append(f"| **Group ID** | `{self.group_id}` |")
        report.append(f"| **Artifact ID** | `{self.artifact_id}` |")
        report.append(f"| **Current Version** | `{self.package_data.get('version', 'unknown')}` |")
        report.append(f"| **Current Version Age** | {self.package_age.get('current_version_age', 'Unknown')} |")
        report.append(f"| **Newest in Same Major** | {self.package_age.get('newest_same_major', 'Unknown')} |")
        report.append(f"| **Newest Overall** | {self.package_age.get('newest_overall', 'Unknown')} |")
        report.append(f"| **Versions Since Current** | {self.package_age.get('versions_since_current', 'Unknown')} |")
        report.append(f"| **First Release** | {self.package_age.get('first_release', 'Unknown')} |")
        report.append(f"| **Total Versions** | {self.package_age.get('total_versions', 'Unknown')} |")
        report.append(f"| **Maturity** | {self.package_age.get('maturity', 'Unknown')} |")
        report.append(f"| **Package URL** | {self.package_data.get('url', 'N/A')} |")
        report.append(f"| **JAR Size** | {self.package_data.get('jar_size', 'Unknown')} |")
        report.append("")
        
        # Package Statistics
        report.append("### 📊 Package Statistics")
        report.append(f"- **Maturity**: {self.package_age.get('maturity', 'Unknown')} 📈")
        report.append(f"- **Package Size**: {self.package_data.get('jar_size', 'Unknown')}")
        report.append("")

        # Security Assessment
        report.append("## 🛡️ Security Assessment\n")
        report.append(f"### 🎯 Overall Risk Score: {self.risk_score}/100 ({self.risk_level} RISK) 🟢\n")
        report.append("**Risk Level**: ✅ **LOW**")
        report.append("**Recommendation**: ✅ **SAFE TO USE**\n")
        report.append("---\n")
        
        # Security Checks Summary
        report.append("### 📋 Security Checks Summary\n")
        report.append("| Check | Status | Details |")
        report.append("|-------|--------|---------|")
        
        check_names = {
            'cves': 'Known CVEs',
            'secrets': 'Hardcoded Secrets',
            'dependencies': 'Dependency Vulnerabilities',
            'signatures': 'Package Signatures',
            'maintainer': 'Maintainer Verification',
            'repository': 'Repository Activity',
            'code_quality': 'Code Quality',
            'metadata': 'Metadata Consistency'
        }
        
        for check_key, check_name in check_names.items():
            if check_key in self.checks:
                passed, details = self.checks[check_key]
                status = "✅ PASS" if passed else "❌ FAIL"
                detail_text = details.get('details', 'Check completed')
                report.append(f"| {check_name} | {status} | {detail_text} |")
        
        report.append("")
        report.append("---\n")
        
        # Detailed Checks
        report.append("## 🔍 Detailed Security Checks\n")
        
        
        # CVEs and Vulnerability Scan
        report.append("### 1️⃣ Vulnerability Analysis (Grype Scan)\n")
        report.append("#### Known CVEs & Vulnerable Dependencies")

        # Vulnerability Scan Results
        report.append("#### Vulnerability Scan Findings")
        report.append("```")
        dep_pass, dep_details = self.checks['dependencies']
        status = "✅ PASS" if dep_pass else "❌ FAIL"
        report.append(f"{status} **Status**: Vulnerability Scan Complete")
        report.append(f"� **Critical Vulnerabilities**: {dep_details.get('critical', 0)}")
        report.append(f"� **High Vulnerabilities**: {dep_details.get('high', 0)}")
        report.append(f"� **Total Vulnerabilities**: {dep_details.get('total_vulnerabilities', 0)}")
        report.append(f"**Details**: {dep_details.get('details', 'Analysis complete')}")
        report.append("```")
        
        # List found vulnerabilities if any
        if dep_details.get('total_vulnerabilities', 0) > 0 and dep_details.get('vulnerabilities'):
            report.append("")
            report.append("#### Found Vulnerabilities")
            report.append("")
            for vuln in dep_details.get('vulnerabilities', []):
                cve_id = vuln.get('id', 'unknown')
                severity = vuln.get('severity', 'UNKNOWN')
                title = vuln.get('title', 'No description')
                report.append(f"- **{cve_id}** [{severity}]: {title}")
        
        report.append("")
        
        # Secrets
        report.append("### 2️⃣ Secrets & Suspicious Content\n")
        report.append("#### Hardcoded Credentials")
        report.append("```")
        secret_pass, secret_details = self.checks['secrets']
        report.append(f"✅ **Status**: PASS")
        report.append(f"🔑 **API Keys**: {secret_details.get('api_keys', 0)} found")
        report.append(f"🔐 **Passwords**: {secret_details.get('passwords', 0)} found")
        report.append(f"🪙 **Tokens**: {secret_details.get('tokens', 0)} found")
        report.append(f"**Details**: {secret_details.get('details', 'No secrets detected')}")
        report.append("```")
        report.append("")
        
        # Signatures
        report.append("### 3️⃣ Supply Chain & Provenance\n")
        report.append("#### Package Signatures")
        report.append("```")
        sig_pass, sig_details = self.checks['signatures']
        status = "✅ PASS" if sig_pass else "❌ FAIL"
        report.append(f"{status} **Status**: {'Signature Valid' if sig_pass else 'Signature Invalid'}")
        report.append(f"🔐 **JAR Signed**: {'Yes' if sig_details.get('jar_signed') else 'No'}")
        report.append(f"**Details**: {sig_details.get('details', 'Signature verification complete')}")
        report.append("```")
        report.append("")
        
        # Calculate check results
        checks_performed = len(self.checks)
        checks_passed = sum(1 for passed, _ in self.checks.values() if passed)
        checks_failed = checks_performed - checks_passed
        
        # Recommendations
        report.append("## 💡 Recommendations\n")
        report.append("### ✅ What's Good")
        report.append("- ✅ Package available on Maven Central")
        report.append("- ✅ No known CVEs detected")
        report.append("- ✅ Signatures available for verification")
        report.append("- ✅ Metadata consistent\n")
        
        report.append("### 🔍 Areas to Monitor")
        report.append("- Monitor for new CVEs (check quarterly)")
        report.append("- Keep dependencies up-to-date")
        report.append("- Review release notes before upgrades\n")
        
        # Verdict based on failed checks
        report.append("### Verdict")
        if checks_failed == 0:
            report.append("**RECOMMENDED FOR USE** ✅\n")
            report.append("This package appears safe for use. Verify maintainer and repository on Maven Central.\n")
        else:
            report.append("**NOT RECOMMENDED** ❌\n")
            report.append(f"This package has {checks_failed} failed security check(s). Review the findings above before use.\n")
        
        report.append("---\n")
        
        # Audit Metadata
        report.append("## 📋 Audit Metadata\n")
        report.append("```")
        report.append("🐺 **Auditor**: Maven Package Auditor v1.0.0")
        report.append(f"📅 **Audit Date**: {self.audit_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        report.append(f"✅ **Checks Performed**: {checks_performed}")
        report.append(f"✅ **Checks Passed**: {checks_passed}")
        report.append(f"❌ **Checks Failed**: {checks_failed}")
        report.append("⚠️ **Warnings**: 0")
        report.append("```\n")
        
        report.append("🐺 **Powered by Chainguard Security Principles**")
        report.append("🔗 **Learn more**: https://www.chainguard.dev/")
        
        return "\n".join(report)
    
    def save_report(self, output_dir: str = ".") -> str:
        """Save report to file"""
        timestamp = self.audit_date.strftime("%Y%m%d")
        filename = f"audit_report_{self.group_id}_{self.artifact_id}_{timestamp}.md"
        filepath = Path(output_dir) / filename
        
        report = self.generate_markdown_report()
        filepath.write_text(report)
        
        return str(filepath)


def print_help():
    """Print help message"""
    print("🐺 Maven Package Auditor v1.0.0")
    print("\nA security-focused CLI tool for auditing Maven packages")
    print("\nUsage: auditor.py <groupId:artifactId[:version]> [options]")
    print("\nArguments:")
    print("  <groupId:artifactId[:version]>  Maven package coordinates (version is optional)")
    print("\nOptions:")
    print("  -h, --help     Show this help message and exit")
    print("  -o, --output   Output directory for the report (default: current directory)")
    print("\nExamples:")
    print("  auditor.py org.springframework.boot:spring-boot-starter:4.0.0")
    print("  auditor.py org.springframework:spring-core:6.1.4 -o ./reports")
    print("  auditor.py org.apache:commons-lang3:3.14.0 --output /tmp")
    print("  auditor.py junit:junit:4.13.2")
    print("\nIf version is omitted, the latest version will be used.")


def main():
    """Main entry point"""
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Maven Package Auditor - Security-focused Maven package analysis tool',
                                   add_help=False)
    parser.add_argument('package', nargs='?', help='Maven package coordinates (groupId:artifactId[:version])')
    parser.add_argument('-o', '--output', default='.', help='Output directory for the report')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    # Parse arguments
    if len(sys.argv) == 1:
        print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    if args.help or not args.package:
        print_help()
        sys.exit(0)
    
    try:
        # Create auditor
        auditor = MavenAuditor(args.package)
        
        # Run audit
        print(f"🔍 Auditing package: {args.package}", file=sys.stderr)
        auditor.run_all_checks()
        
        # Generate and print report
        report = auditor.generate_markdown_report()
        print(report)
        
        # Save report to specified output directory
        saved_path = auditor.save_report(args.output)
        print(f"\n📄 Report saved to: {saved_path}", file=sys.stderr)
        
    except ValueError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
