import os
import hashlib
import logging
import re
import json
from datetime import datetime
from typing import List, Dict, Optional, Set, Any
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.core.exceptions import AzureError, HttpResponseError

# Configure logging - avoid exposing sensitive data in logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Security: Salt for hashing (in production, store this securely, e.g., Azure Key Vault)
# This ensures unique hashes even across different audit runs
HASH_SALT = os.environ.get('AUDIT_HASH_SALT', 'default-audit-salt-2026')

# Compliance: Allowed Azure regions for data residency (OPTIONAL)
# Set this to None to disable compliance checking (default for smaller companies)
# Bigger companies with compliance requirements can configure this:
ALLOWED_REGIONS: Optional[Set[str]] = None  # Disabled by default

# Example for companies with EU data residency requirements:
# ALLOWED_REGIONS: Set[str] = {
#     'westeurope', 'northeurope', 'germanywestcentral',
#     'francecentral', 'switzerlandnorth'
# }

def anonymize_identifier(sensitive_value: str, prefix: str = "") -> str:
    """
    Anonymizes sensitive identifiers using SHA-256 hashing with salt.
    Returns a consistent anonymized ID for the same input.
    """
    try:
        if not sensitive_value:
            return f"{prefix}unknown"
        
        # Use SHA-256 with salt for secure, one-way anonymization
        salted_value = f"{HASH_SALT}{sensitive_value}"
        hash_object = hashlib.sha256(salted_value.encode('utf-8'))
        # Take first 12 characters of hex digest for readability
        anonymized = hash_object.hexdigest()[:12]
        return f"{prefix}{anonymized}" if prefix else anonymized
    except Exception as e:
        logging.error(f"Anonymization error occurred (no sensitive data logged)")
        return f"{prefix}error"

def get_safe_data_for_external_sharing(findings: List[Dict]) -> List[Dict]:
    """
    Returns only the anonymized findings that are safe to share externally.
    IMPORTANT: Do NOT include resource_mapping in external shares!
    """
    return findings  # Already anonymized, safe to share

def generate_client_ready_report(ai_analyzed_text: str, resource_mapping: Dict[str, Any]) -> str:
    """
    Converts AI-analyzed text with anonymized IDs back to real resource names for client reports.
    
    Args:
        ai_analyzed_text: Text from AI (e.g., Gemini Pro) containing anonymized identifiers
        resource_mapping: Dictionary mapping anonymized IDs to real resource information
        
    Returns:
        Client-ready Markdown report with real resource names
        
    Example usage:
        # 1. Send audit_results to Gemini Pro for analysis
        ai_response = gemini.analyze(audit_results)
        
        # 2. Convert AI response to client-ready report
        client_report = generate_client_ready_report(ai_response, resource_mapping)
        
        # 3. Save or present to client
        with open('client_security_report.md', 'w', encoding='utf-8') as f:
            f.write(client_report)
    """
    
    client_report = ai_analyzed_text
    
    # Track replacements for summary
    replacements_made = []
    
    # Sort keys by length (longest first) to avoid partial replacements
    sorted_keys = sorted(resource_mapping.keys(), key=len, reverse=True)
    
    for anonymized_id in sorted_keys:
        real_info = resource_mapping[anonymized_id]
        
        # Handle different types of anonymized IDs
        if anonymized_id.startswith('storage_'):
            # Storage account - replace with detailed info
            if isinstance(real_info, dict):
                real_name = real_info.get('name', 'Unknown')
                location = real_info.get('location', 'Unknown')
                subscription = real_info.get('subscription', 'Unknown')
                
                # Create replacement text with context
                replacement = f"**{real_name}** (Location: {location}, Subscription: {subscription})"
                
                # Find and replace all occurrences
                if anonymized_id in client_report:
                    client_report = client_report.replace(anonymized_id, replacement)
                    replacements_made.append(f"Storage: {anonymized_id} → {real_name}")
                    
        elif anonymized_id.startswith('sub_'):
            # Subscription name
            if isinstance(real_info, str):
                replacement = f"**{real_info}**"
                if anonymized_id in client_report:
                    client_report = client_report.replace(anonymized_id, replacement)
                    replacements_made.append(f"Subscription: {anonymized_id} → {real_info}")
                    
        elif anonymized_id.startswith('id_'):
            # Subscription ID - usually keep anonymized in client reports
            # But replace with user-friendly label
            if isinstance(real_info, str):
                # Extract subscription name if available
                sub_name = "Subscription"
                for key, val in resource_mapping.items():
                    if key.startswith('sub_') and isinstance(val, str):
                        sub_name = val
                        break
                replacement = f"[{sub_name}]"
                if anonymized_id in client_report:
                    client_report = client_report.replace(anonymized_id, replacement)
    
    # Add professional header and footer to the report
    current_date = datetime.now().strftime("%d %B %Y")
    
    header = f"""# Azure Security Audit Report

**Report Date:** {current_date}  
**Report Type:** Storage Account Security Assessment  
**Status:** CONFIDENTIAL - Internal Use Only

---

"""
    
    footer = f"""

---

## Report Metadata

- **Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Resources De-anonymized:** {len(replacements_made)}
- **Analysis Tool:** Azure Security Audit Script with AI Analysis

### Disclaimer
This report contains sensitive information about your Azure infrastructure. Please handle with care and share only with authorized personnel.

---

*Dit rapport is automatisch gegenereerd en bevat real-time beveiligingsinformatie.*
"""
    
    # Combine header + content + footer
    final_report = header + client_report + footer
    
    return final_report

def demo_client_report_generation():
    """
    Demonstrates how to use generate_client_ready_report with example data.
    Useful for testing the de-anonymization workflow.
    """
    # Example AI-analyzed text with anonymized IDs
    example_ai_response = """
## Security Analysis Results

### Critical Findings

We identified security issues in storage_abc123def456 which requires immediate attention.
The resource is deployed in sub_xyz789ghi012 under subscription id_jkl345mno678.

**Recommendations:**
1. Disable public blob access on storage_abc123def456
2. Ensure TLS 1.2+ is enforced across all resources in sub_xyz789ghi012
3. Review access policies for storage_abc123def456

### Summary
Total issues found: 2
Severity: High
"""
    
    # Example resource mapping
    example_mapping = {
        'storage_abc123def456': {
            'name': 'prodstorageaccount',
            'location': 'westeurope',
            'subscription': 'Production Environment',
            'id': '/subscriptions/12345/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/prodstorageaccount'
        },
        'sub_xyz789ghi012': 'Production Environment',
        'id_jkl345mno678': '12345-67890-abcde-fghij'
    }
    
    # Generate client-ready report
    client_report = generate_client_ready_report(example_ai_response, example_mapping)
    
    print("\n" + "="*70)
    print("📄 DEMO: CLIENT-READY REPORT")
    print("="*70)
    print(client_report)
    print("="*70)
    
    return client_report

def prompt_output_directory() -> Optional[str]:
    """
    Prompts user for output directory and validates it.
    Creates the directory if it doesn't exist (with user permission).
    
    Returns:
        Valid directory path or None if user cancels
    """
    while True:
        print("\n" + "="*70)
        print("📁 OUTPUT DIRECTORY CONFIGURATIE")
        print("="*70)
        
        user_input = input("\nWelke map dient dit te worden opgeslagen? (of druk Enter voor huidige map): ").strip()
        
        # Default to current directory if empty
        if not user_input:
            output_dir = os.getcwd()
            print(f"✅ Gebruik huidige map: {output_dir}")
            return output_dir
        
        # Validate path
        try:
            # Normalize the path
            output_dir = os.path.abspath(os.path.expanduser(user_input))
            
            # Check if path exists
            if os.path.exists(output_dir):
                # Check if it's a directory
                if not os.path.isdir(output_dir):
                    print(f"❌ Error: '{output_dir}' is een bestand, geen map.")
                    retry = input("Probeer opnieuw? (j/n): ").strip().lower()
                    if retry != 'j':
                        return None
                    continue
                
                # Check if we have write permissions
                if not os.access(output_dir, os.W_OK):
                    print(f"❌ Error: Geen schrijfrechten voor '{output_dir}'")
                    retry = input("Probeer opnieuw? (j/n): ").strip().lower()
                    if retry != 'j':
                        return None
                    continue
                
                print(f"✅ Map gevonden en beschrijfbaar: {output_dir}")
                return output_dir
            
            else:
                # Directory doesn't exist - ask to create
                print(f"⚠️ Map bestaat niet: {output_dir}")
                create = input("Wilt u deze map aanmaken? (j/n): ").strip().lower()
                
                if create == 'j':
                    try:
                        os.makedirs(output_dir, exist_ok=True)
                        print(f"✅ Map aangemaakt: {output_dir}")
                        logging.info(f"Created output directory: {output_dir}")
                        return output_dir
                    except PermissionError:
                        print(f"❌ Error: Geen rechten om map aan te maken: {output_dir}")
                        retry = input("Probeer opnieuw? (j/n): ").strip().lower()
                        if retry != 'j':
                            return None
                        continue
                    except Exception as e:
                        print(f"❌ Error bij aanmaken map: {type(e).__name__}: {e}")
                        retry = input("Probeer opnieuw? (j/n): ").strip().lower()
                        if retry != 'j':
                            return None
                        continue
                else:
                    retry = input("Probeer een andere map? (j/n): ").strip().lower()
                    if retry != 'j':
                        return None
                    continue
                    
        except Exception as e:
            print(f"❌ Ongeldige mapnaam: {type(e).__name__}: {e}")
            retry = input("Probeer opnieuw? (j/n): ").strip().lower()
            if retry != 'j':
                return None
            continue

def save_ai_input_json(findings: List[Dict], output_dir: str = '.', filename: str = 'ai_input.json') -> None:
    """
    Saves anonymized findings to a clean JSON file for AI analysis.
    This file is SAFE to send to external services like Gemini Pro.
    
    Args:
        findings: List of anonymized security findings
        output_dir: Directory where file should be saved (default: current directory)
        filename: Output filename (default: 'ai_input.json')
    """
    try:
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        
        logging.info(f"AI input saved to {filepath} ({len(findings)} findings)")
        print(f"\n✅ AI input JSON saved: {filepath}")
        print(f"   - {len(findings)} findings")
        print(f"   - Safe to share with external AI services")
        
    except Exception as e:
        logging.error(f"Failed to save AI input JSON: {type(e).__name__}")
        print(f"\n❌ Failed to save {filename}: {e}")

def save_local_correlation_markdown(findings: List[Dict], resource_mapping: Dict[str, Any], 
                                   output_dir: str = '.', filename: str = 'local_mapping.md') -> None:
    """
    Creates a Markdown table showing the correlation between hashed and real resource names.
    This file contains SENSITIVE data and should NEVER be shared externally.
    
    Args:
        findings: List of anonymized security findings
        resource_mapping: Dictionary mapping anonymized IDs to real resource information
        output_dir: Directory where file should be saved (default: current directory)
        filename: Output filename (default: 'local_mapping.md')
    """
    try:
        filepath = os.path.join(output_dir, filename)
        
        # Build the markdown content
        markdown_lines = []
        markdown_lines.append("# Local Resource Mapping")
        markdown_lines.append("")
        markdown_lines.append("⚠️ **CONFIDENTIAL - DO NOT SHARE EXTERNALLY**")
        markdown_lines.append("")
        markdown_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        markdown_lines.append("")
        markdown_lines.append("## Resource Correlation Table")
        markdown_lines.append("")
        markdown_lines.append("| Hashed Name | Real Name | Subscription | Location | Issues |")
        markdown_lines.append("|-------------|-----------|--------------|----------|--------|")
        
        # Process each finding
        for finding in findings:
            hashed_name = finding.get('resource_name_anonymized', 'Unknown')
            real_info = resource_mapping.get(hashed_name, {})
            
            if isinstance(real_info, dict):
                real_name = real_info.get('name', 'Unknown')
                subscription = real_info.get('subscription', 'Unknown')
                location = finding.get('location', 'Unknown')
                issues = ', '.join(finding.get('issues', ['None']))
                
                # Escape pipe characters in issues for markdown
                issues_escaped = issues.replace('|', '\\|')
                
                markdown_lines.append(
                    f"| `{hashed_name}` | **{real_name}** | {subscription} | {location} | {issues_escaped} |"
                )
        
        markdown_lines.append("")
        markdown_lines.append("---")
        markdown_lines.append("")
        markdown_lines.append("## Notes")
        markdown_lines.append("")
        markdown_lines.append("- **Hashed Name**: Anonymized identifier used in AI analysis")
        markdown_lines.append("- **Real Name**: Actual Azure resource name")
        markdown_lines.append("- **Subscription**: Azure subscription containing the resource")
        markdown_lines.append("- **Location**: Azure region where the resource is deployed")
        markdown_lines.append("- **Issues**: Security issues found during audit")
        markdown_lines.append("")
        markdown_lines.append("### Security Reminder")
        markdown_lines.append("")
        markdown_lines.append("This file maps anonymized identifiers back to real resource names.")
        markdown_lines.append("Keep this file secure and never share it with external services.")
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(markdown_lines))
        
        logging.info(f"Local correlation mapping saved to {filepath}")
        print(f"\n✅ Local correlation Markdown saved: {filepath}")
        print(f"   - {len(findings)} resources mapped")
        print(f"   - ⚠️ CONFIDENTIAL - Keep this file secure!")
        
    except Exception as e:
        logging.error(f"Failed to save correlation markdown: {type(e).__name__}")
        print(f"\n❌ Failed to save {filename}: {e}")

def run_security_audit(allowed_regions: Optional[Set[str]] = None, enable_compliance_check: bool = False) -> Optional[tuple[List[Dict], Dict[str, str]]]:
    """
    Runs security audit on Azure storage accounts across ALL subscriptions in the tenant.
    Returns tuple of (anonymized_findings, resource_mapping) or None if audit fails.
    
    Args:
        allowed_regions: Set of allowed Azure regions for data residency compliance.
                        If None, uses ALLOWED_REGIONS constant. Only used if enable_compliance_check=True.
        enable_compliance_check: If True, checks data residency compliance (for bigger companies).
                                If False (default), location is auditable but not validated.
    
    resource_mapping contains the mapping between anonymized IDs and real resource names
    for local reference only - DO NOT send this to external services.
    
    Location data is ALWAYS included in findings for auditability (not hashed).
    """
    findings = []
    resource_mapping = {}  # Maps anonymized IDs to real names (LOCAL ONLY)
    
    # Determine if compliance checking is enabled
    if enable_compliance_check:
        if allowed_regions is None:
            allowed_regions = ALLOWED_REGIONS
        if allowed_regions is None:
            logging.warning("Compliance check enabled but no allowed regions configured. Skipping compliance validation.")
            enable_compliance_check = False
    
    try:
        # 1. Authenticatie: Gebruikt je lokale Azure CLI of VS Code login
        # Veilig: Geen hardcoded credentials
        logging.info("Initiating Azure authentication...")
        credential = DefaultAzureCredential()
        
    except Exception as e:
        logging.error("Authentication failed. Ensure you're logged in via Azure CLI or VS Code.")
        logging.error(f"Error type: {type(e).__name__}")
        return None
    
    try:
        # 2. Get ALL subscriptions in the tenant
        logging.info("Retrieving subscription information...")
        subscription_client = SubscriptionClient(credential)
        
        # Get all subscriptions with proper error handling
        subscriptions = list(subscription_client.subscriptions.list())
        
        if not subscriptions:
            logging.error("No Azure subscriptions found for this account.")
            return None
        
        logging.info(f"Found {len(subscriptions)} subscription(s) in tenant. Starting audit...")
        print(f"\n{'='*70}")
        print(f"🔍 TENANT-WIDE SECURITY AUDIT")
        print(f"{'='*70}")
        print(f"Total Subscriptions: {len(subscriptions)}")
        if enable_compliance_check and allowed_regions:
            print(f"Compliance Check: ✅ ENABLED")
            print(f"Allowed Regions: {', '.join(sorted(allowed_regions))}")
        else:
            print(f"Compliance Check: ℹ️ DISABLED (location auditable only)")
        print(f"{'='*70}\n")
        
    except HttpResponseError as e:
        logging.error(f"Azure API error while retrieving subscriptions. Status code: {e.status_code}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error retrieving subscription: {type(e).__name__}")
        return None

    # 3. Loop through ALL subscriptions
    total_account_count = 0
    
    for sub_index, subscription in enumerate(subscriptions, 1):
        try:
            subscription_id = subscription.subscription_id
            
            # Anonymize sensitive subscription information
            anonymized_sub_name = anonymize_identifier(subscription.display_name, prefix="sub_")
            anonymized_sub_id = anonymize_identifier(subscription_id, prefix="id_")
            
            # Store mapping for local reference (DO NOT send to external services)
            resource_mapping[anonymized_sub_id] = subscription_id
            resource_mapping[anonymized_sub_name] = subscription.display_name

            print(f"\n[{sub_index}/{len(subscriptions)}] 📋 Subscription: {subscription.display_name}")
            print(f"            Subscription ID: {subscription_id}")
            logging.info(f"Auditing subscription {sub_index}/{len(subscriptions)}: {subscription.display_name}")
            
        except Exception as e:
            logging.error(f"Error processing subscription metadata (skipping): {type(e).__name__}")
            continue

        try:
            # 4. Storage Account Audit for this subscription
            logging.info(f"Scanning storage accounts in subscription: {subscription.display_name}...")
            storage_client = StorageManagementClient(credential, subscription_id)
            
            account_count = 0
        
            for account in storage_client.storage_accounts.list():
                try:
                    account_count += 1
                    total_account_count += 1
                    
                    # Check op Public Blob Access
                    is_public = getattr(account, 'allow_blob_public_access', False)
                    
                    # Check Minimum TLS Version (should be TLS 1.2 or higher)
                    min_tls_version = getattr(account, 'minimum_tls_version', None)
                    is_tls_compliant = True
                    if min_tls_version:
                        # Check if TLS version is lower than 1.2
                        is_tls_compliant = min_tls_version in ['TLS1_2', 'TLS1_3']
                    else:
                        # No TLS version set means potentially insecure
                        is_tls_compliant = False
                    
                    # Check Data Residency Compliance (OPTIONAL - only if enabled)
                    is_compliant_region = True  # Default to compliant if check disabled
                    if enable_compliance_check and allowed_regions:
                        is_compliant_region = account.location.lower() in {r.lower() for r in allowed_regions}
                    
                    # Anonymize storage account name
                    anonymized_account_name = anonymize_identifier(account.name, prefix="storage_")
                    
                    # Store mapping for local reference (DO NOT send to external services)
                    resource_mapping[anonymized_account_name] = {
                        "name": account.name,
                        "id": account.id,
                        "location": account.location,  # Location kept for auditability
                        "subscription": subscription.display_name,
                        "min_tls_version": min_tls_version
                    }
                    
                    # Determine status and issues
                    issues = []
                    severity = "Low"
                    
                    if is_public:
                        issues.append("Public Blob Access staat AAN")
                        severity = "High"
                    
                    if not is_tls_compliant:
                        if min_tls_version:
                            issues.append(f"Minimum TLS Version te laag: {min_tls_version} (vereist: TLS1_2 of hoger)")
                        else:
                            issues.append("Minimum TLS Version niet ingesteld (vereist: TLS1_2 of hoger)")
                        severity = "High"
                    
                    # Only check compliance if enabled
                    if enable_compliance_check and not is_compliant_region:
                        issues.append(f"Data Residency Violation - Region '{account.location}' niet toegestaan")
                        severity = "High" if severity != "High" else "Critical"
                    
                    # Determine display status
                    if issues:  # Has any issues
                        status = "⚠️ ONVEILIG"
                    else:
                        status = "✅ VEILIG"
                    
                    # Store anonymized data for external sharing (safe for Gemini)
                    if issues:  # Only store if there are issues
                        finding = {
                            "resource_name_anonymized": anonymized_account_name,  # Anonymized
                            "subscription_id_anonymized": anonymized_sub_id,       # Anonymized
                            "subscription_name_anonymized": anonymized_sub_name,   # Anonymized
                            "type": "Storage Account",
                            "issues": issues,
                            "severity": severity,
                            "location": account.location,  # NOT hashed - kept for auditability
                            "min_tls_version": min_tls_version,  # Security configuration info
                            "compliant_region": is_compliant_region if enable_compliance_check else None
                        }
                        findings.append(finding)
                        logging.warning(f"Security issue(s) found in {account.name}: {', '.join(issues)}")
                    
                    # Display REAL names locally for immediate action
                    print(f"  [{status}] {account.name} (Location: {account.location})")
                    if issues:
                        for issue in issues:
                            print(f"           └─ ⚠️ {issue}")
                        print(f"           └─ Resource ID: {account.id}")
                
                except Exception as e:
                    logging.error(f"Error processing storage account (account skipped): {type(e).__name__}")
                    continue  # Skip this account and continue with others
            
            if account_count == 0:
                print(f"  ℹ️ No storage accounts found in this subscription")
                logging.warning(f"No storage accounts found in subscription: {subscription.display_name}")
            else:
                print(f"  ✓ Scanned {account_count} storage account(s)")
                logging.info(f"Successfully scanned {account_count} storage account(s) in {subscription.display_name}")
                
        except HttpResponseError as e:
            logging.error(f"Azure API error while scanning subscription {subscription.display_name}. Status code: {e.status_code}")
            print(f"  ❌ Error scanning this subscription (API error)")
            continue  # Continue with next subscription
        except AzureError as e:
            logging.error(f"Azure service error in subscription {subscription.display_name}: {type(e).__name__}")
            print(f"  ❌ Error scanning this subscription (Azure error)")
            continue  # Continue with next subscription
        except Exception as e:
            logging.error(f"Unexpected error scanning subscription {subscription.display_name}: {type(e).__name__}")
            print(f"  ❌ Unexpected error scanning this subscription")
            continue  # Continue with next subscription


    return findings, resource_mapping

if __name__ == "__main__":
    try:
        # Default: Location auditable, no compliance checking
        audit_result = run_security_audit()
        
        # For bigger companies with data residency requirements, enable compliance:
        # allowed_eu_regions = {'westeurope', 'northeurope', 'germanywestcentral', 'francecentral'}
        # audit_result = run_security_audit(allowed_regions=allowed_eu_regions, enable_compliance_check=True)
        
        if audit_result is None:
            print("\n❌ Audit gefaald. Controleer de logs voor details.")
            logging.error("Security audit failed to complete.")
        else:
            audit_results, resource_mapping = audit_result
            
            print(f"\n{'='*70}")
            print(f"--- AUDIT COMPLEET ---")
            print(f"{'='*70}")
            print(f"Total Storage Accounts Scanned: {total_account_count if 'total_account_count' in dir() else 'N/A'}")
            print(f"Total Issues Found: {len(audit_results)}")
            print(f"{'='*70}")
            
            if audit_results:
                print(f"\n⚠️ {len(audit_results)} beveiligingsissue(s) gevonden!")
                print("\n📋 Kwetsbare Resources (LOKAAL - Niet delen):")
                print("-" * 60)
                
                for idx, finding in enumerate(audit_results, 1):
                    anon_name = finding["resource_name_anonymized"]
                    real_info = resource_mapping.get(anon_name, {})
                    
                    if isinstance(real_info, dict):
                        print(f"\n🔴 [{idx}] {real_info.get('name', 'Unknown')}")
                        print(f"   Subscription: {real_info.get('subscription', 'Unknown')}")
                        print(f"   Resource ID: {real_info.get('id', 'Unknown')}")
                        print(f"   Location: {finding.get('location', 'Unknown')}")
                        print(f"   Minimum TLS Version: {real_info.get('min_tls_version', 'Not Set')}")
                        if finding.get('compliant_region') is not None:
                            print(f"   Compliant Region: {'✅ Yes' if finding.get('compliant_region') else '❌ No'}")
                        print(f"   Issues: {', '.join(finding.get('issues', ['Unknown']))}")
                        print(f"   Severity: {finding.get('severity', 'Unknown')}")
                
            else:
                print("\n✅ Geen kritieke beveiligingsissues gevonden.")
            
            print(f"\n{'='*70}")
            print("📤 DATA VOOR EXTERNE ANALYSE (Veilig om te delen):")
            print(f"{'='*70}")
            print("\n⚠️ BELANGRIJK: De 'audit_results' variabele bevat ALLEEN geanonimiseerde data.")
            print("Deze is veilig om naar Gemini Pro of andere externe services te sturen.")
            print("\n⚠️ DEEL NOOIT de 'resource_mapping' variabele - deze bevat echte resource namen!")
            print(f"\nAantal findings in veilige dataset: {len(audit_results)}")
            
            # Example: How to get data safe for external sharing
            safe_data = get_safe_data_for_external_sharing(audit_results)
            print(f"\nGebruik 'safe_data' om naar Gemini te sturen: {len(safe_data)} items")
            
            print(f"\n{'='*70}")
            print("📝 WORKFLOW VOOR KLANTRAPPORTAGE:")
            print(f"{'='*70}")
            print("\n1. Stuur 'safe_data' naar Gemini Pro voor AI-analyse")
            print("2. Ontvang geanalyseerde tekst met aanbevelingen")
            print("3. Gebruik generate_client_ready_report() om te de-anonymiseren")
            print("\nVoorbeeld code:")
            print("  # ai_response = gemini.analyze(safe_data)")
            print("  # client_report = generate_client_ready_report(ai_response, resource_mapping)")
            print("  # with open('client_report.md', 'w', encoding='utf-8') as f:")
            print("  #     f.write(client_report)")
            print("\nTest de functie met: demo_client_report_generation()")
            
            # Prompt user for output directory
            output_directory = prompt_output_directory()
            
            if output_directory is None:
                print("\n⚠️ Bestandsopslag geannuleerd door gebruiker.")
                logging.warning("File saving cancelled by user.")
            else:
                # Automatically save files for AI analysis and local reference
                print(f"\n{'='*70}")
                print("💾 SAVING FILES...")
                print(f"{'='*70}")
                
                # Save anonymized findings as JSON (safe for AI)
                save_ai_input_json(audit_results, output_dir=output_directory, filename='ai_input.json')
                
                # Save local correlation markdown (CONFIDENTIAL)
                save_local_correlation_markdown(audit_results, resource_mapping, 
                                              output_dir=output_directory, filename='local_mapping.md')
                
                print(f"\n{'='*70}")
                print("✅ All files saved successfully!")
                print(f"{'='*70}")
                
    except KeyboardInterrupt:
        print("\n\nAudit onderbroken door gebruiker.")
        logging.info("Audit interrupted by user.")
    except Exception as e:
        print(f"\n❌ Onverwachte fout tijdens audit.")
        logging.critical(f"Critical error in main execution: {type(e).__name__}")