"""Core engine: the NIST SP 800-171 catalog + stack-aware gap assessment + SSP.

Pure standard library. Bundles the real 110-control NIST SP 800-171 Rev. 2
catalog across 14 control families, with the DoD Assessment Methodology point
weights (1/3/5) used to compute the 110-point SPRS score (max 110, floor -203).

A "stack-aware" assessment lets a system owner describe the technology stack
(e.g. {"mfa": true, "siem": "splunk", "fips_crypto": false, ...}) and the
engine infers an implementation status for every control whose evidence keys
match the inventory, flagging gaps with concrete remediation guidance and an
inherited-control hint when a known platform (AWS GovCloud, M365 GCC High,
etc.) typically provides the control.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple

TOOL_NAME = "cmmcmap"
TOOL_VERSION = "1.0.0"


class Status(str, Enum):
    MET = "MET"                  # control implemented, evidence present
    PARTIAL = "PARTIAL"          # partially implemented / planned
    NOT_MET = "NOT_MET"          # required, not implemented -> a gap
    NA = "NA"                    # not applicable to this stack
    UNKNOWN = "UNKNOWN"          # insufficient inventory to determine

    @property
    def rank(self) -> int:
        return {"MET": 0, "NA": 0, "PARTIAL": 2, "UNKNOWN": 3, "NOT_MET": 4}[self.value]


# Controls at or worse than this status count as a "finding" for exit codes.
FAIL_STATUSES = {Status.NOT_MET, Status.PARTIAL}


# 14 NIST SP 800-171 control families (abbrev -> full name).
FAMILIES: Dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PS": "Personnel Security",
    "PE": "Physical Protection",
    "RA": "Risk Assessment",
    "CA": "Security Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}


@dataclass
class Control:
    """A single NIST SP 800-171 security requirement."""
    id: str                       # e.g. "3.1.1"
    family: str                   # e.g. "AC"
    weight: int                   # DoD AM point value: 1, 3, or 5
    title: str
    # Inventory keys that, when truthy, indicate the control is implemented.
    evidence_keys: List[str] = field(default_factory=list)
    # Platforms that commonly provide this control as an inherited/shared resp.
    inherited_from: List[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GapFinding:
    control: str
    family: str
    weight: int
    status: Status
    title: str
    rationale: str
    remediation: str = ""
    inherited_hint: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


def Family(abbrev: str) -> str:
    """Return the full family name for an abbreviation (helper export)."""
    return FAMILIES.get(abbrev, abbrev)


def _c(cid, fam, w, title, ev=None, inh=None, rem=""):
    return Control(cid, fam, w, title, list(ev or []), list(inh or []), rem)


# ---------------------------------------------------------------------------
# The bundled 110-control NIST SP 800-171 Rev. 2 catalog (14 families).
# Identifiers and titles track the published requirement set; weights track the
# DoD Assessment Methodology (NIST MEP Handbook 162) 1/3/5 point deductions.
# ---------------------------------------------------------------------------
CATALOG: List[Control] = [
    # --- 3.1 Access Control (AC) — 22 controls ---
    _c("3.1.1", "AC", 5, "Limit system access to authorized users and processes.",
       ["iam", "access_control"], ["AWS IAM", "Azure AD", "M365 GCC High"],
       "Implement role-based access control and an authoritative identity store."),
    _c("3.1.2", "AC", 5, "Limit access to the transactions/functions users may execute.",
       ["rbac", "least_privilege"], ["AWS IAM", "Azure AD"],
       "Define least-privilege roles; remove standing admin rights."),
    _c("3.1.3", "AC", 1, "Control the flow of CUI in accordance with approved authorizations.",
       ["network_segmentation", "dlp"], ["AWS Security Groups", "Azure NSG"],
       "Enforce CUI boundary with segmentation and data-flow controls."),
    _c("3.1.4", "AC", 1, "Separate duties of individuals to reduce malevolent activity.",
       ["sod", "separation_of_duties"], [],
       "Split privileged duties; require separate approver/implementer roles."),
    _c("3.1.5", "AC", 3, "Employ least privilege, including for privileged accounts.",
       ["least_privilege", "pam"], ["CyberArk", "Azure PIM"],
       "Adopt just-in-time privileged access management."),
    _c("3.1.6", "AC", 1, "Use non-privileged accounts for nonsecurity functions.",
       ["non_privileged_default"], [],
       "Require admins to use standard accounts for routine work."),
    _c("3.1.7", "AC", 1, "Prevent non-privileged users from executing privileged functions; audit them.",
       ["privilege_audit", "audit"], [],
       "Log privileged-function execution and alert on misuse."),
    _c("3.1.8", "AC", 1, "Limit unsuccessful logon attempts.",
       ["account_lockout"], ["Azure AD", "Okta"],
       "Configure lockout thresholds (e.g. 5 attempts)."),
    _c("3.1.9", "AC", 1, "Provide privacy and security notices (logon banners).",
       ["logon_banner"], [],
       "Display an approved use-notification banner at logon."),
    _c("3.1.10", "AC", 1, "Use session lock with pattern-hiding displays.",
       ["session_lock", "screen_lock"], ["GPO", "Intune"],
       "Enforce screen lock after inactivity (e.g. 15 min)."),
    _c("3.1.11", "AC", 1, "Terminate user sessions after a defined condition.",
       ["session_timeout"], [],
       "Auto-terminate idle/expired sessions."),
    _c("3.1.12", "AC", 5, "Monitor and control remote access sessions.",
       ["vpn", "remote_access_monitoring"], ["AWS Client VPN", "Zscaler"],
       "Route remote access through monitored, logged gateways."),
    _c("3.1.13", "AC", 5, "Use cryptographic mechanisms to protect remote access sessions.",
       ["vpn_encryption", "tls"], ["AWS Client VPN"],
       "Require FIPS-validated VPN/TLS for remote sessions."),
    _c("3.1.14", "AC", 1, "Route remote access via managed access control points.",
       ["managed_access_points", "vpn"], [],
       "Funnel remote access through a small set of managed gateways."),
    _c("3.1.15", "AC", 1, "Authorize remote execution of privileged commands.",
       ["privileged_remote_auth"], [],
       "Require explicit authorization for remote privileged commands."),
    _c("3.1.16", "AC", 5, "Authorize wireless access prior to allowing connections.",
       ["wireless_auth"], [],
       "Require pre-authorization and inventory of wireless access."),
    _c("3.1.17", "AC", 5, "Protect wireless access using authentication and encryption.",
       ["wpa2_enterprise", "wireless_encryption"], [],
       "Use WPA2/WPA3-Enterprise with 802.1X."),
    _c("3.1.18", "AC", 5, "Control connection of mobile devices.",
       ["mdm", "mobile_device_management"], ["Intune", "Jamf"],
       "Enroll mobile devices in MDM with conditional access."),
    _c("3.1.19", "AC", 3, "Encrypt CUI on mobile devices and mobile computing platforms.",
       ["mobile_encryption", "disk_encryption"], ["BitLocker", "FileVault"],
       "Enforce full-disk encryption on all mobile endpoints."),
    _c("3.1.20", "AC", 1, "Verify and control connections to external systems.",
       ["external_connection_control"], [],
       "Document and approve external system connections."),
    _c("3.1.21", "AC", 1, "Limit use of portable storage on external systems.",
       ["portable_storage_control", "usb_control"], ["Intune"],
       "Block or control USB/portable storage via policy."),
    _c("3.1.22", "AC", 1, "Control CUI posted/processed on publicly accessible systems.",
       ["public_content_review"], [],
       "Require review before posting content to public systems."),

    # --- 3.2 Awareness and Training (AT) — 3 controls ---
    _c("3.2.1", "AT", 5, "Ensure managers/users are aware of security risks of their activities.",
       ["security_awareness_training"], ["KnowBe4"],
       "Run annual + onboarding security awareness training."),
    _c("3.2.2", "AT", 5, "Ensure personnel are trained to carry out their security duties.",
       ["role_based_training"], [],
       "Provide role-based security training for privileged staff."),
    _c("3.2.3", "AT", 1, "Provide security awareness training on insider threat.",
       ["insider_threat_training"], [],
       "Add insider-threat awareness to the training program."),

    # --- 3.3 Audit and Accountability (AU) — 9 controls ---
    _c("3.3.1", "AU", 5, "Create and retain system audit logs for monitoring/analysis.",
       ["audit", "logging", "siem"], ["CloudTrail", "Azure Monitor", "Splunk"],
       "Centralize audit logs in a SIEM with retention policy."),
    _c("3.3.2", "AU", 3, "Ensure actions can be uniquely traced to individual users.",
       ["user_attribution", "audit"], [],
       "Log per-user identity on all auditable events."),
    _c("3.3.3", "AU", 1, "Review and update logged events.",
       ["log_review_policy"], [],
       "Periodically review and tune the set of logged events."),
    _c("3.3.4", "AU", 1, "Alert on audit logging process failure.",
       ["log_failure_alert"], ["Splunk", "Datadog"],
       "Alert when logging pipelines fail or stop."),
    _c("3.3.5", "AU", 3, "Correlate audit record review/analysis for investigation.",
       ["log_correlation", "siem"], ["Splunk", "Sentinel"],
       "Use SIEM correlation rules for cross-source analysis."),
    _c("3.3.6", "AU", 1, "Provide audit record reduction and report generation.",
       ["log_reporting"], ["Splunk"],
       "Enable on-demand reporting/reduction from the SIEM."),
    _c("3.3.7", "AU", 1, "Provide authoritative time source for timestamps.",
       ["ntp", "time_sync"], [],
       "Sync all systems to an authoritative NTP source."),
    _c("3.3.8", "AU", 5, "Protect audit information and tools from unauthorized access.",
       ["log_integrity", "log_access_control"], ["CloudTrail (immutable)"],
       "Restrict and integrity-protect audit logs (WORM/immutable)."),
    _c("3.3.9", "AU", 1, "Limit management of audit functionality to a privileged subset.",
       ["audit_admin_restriction"], [],
       "Restrict audit configuration to a small privileged group."),

    # --- 3.4 Configuration Management (CM) — 9 controls ---
    _c("3.4.1", "CM", 5, "Establish/maintain baseline configurations and inventories.",
       ["baseline_config", "asset_inventory"], ["AWS Config", "Intune"],
       "Maintain configuration baselines + an authoritative asset inventory."),
    _c("3.4.2", "CM", 5, "Establish/enforce security configuration settings.",
       ["hardening", "cis_benchmark"], ["CIS Benchmarks", "STIG"],
       "Apply CIS/STIG hardening baselines and enforce drift detection."),
    _c("3.4.3", "CM", 1, "Track, review, approve/disapprove, and log config changes.",
       ["change_management"], ["ServiceNow", "Jira"],
       "Run a change-control board with logged approvals."),
    _c("3.4.4", "CM", 1, "Analyze security impact of changes prior to implementation.",
       ["change_impact_analysis"], [],
       "Require security-impact review in the change process."),
    _c("3.4.5", "CM", 1, "Define/enforce access restrictions for changes.",
       ["change_access_control"], [],
       "Restrict who may make changes to systems."),
    _c("3.4.6", "CM", 5, "Employ least functionality (essential capabilities only).",
       ["least_functionality", "hardening"], [],
       "Disable nonessential services, ports, and protocols."),
    _c("3.4.7", "CM", 5, "Restrict/disable nonessential programs, ports, protocols, services.",
       ["port_protocol_control"], [],
       "Maintain a deny-by-default ports/protocols/services policy."),
    _c("3.4.8", "CM", 5, "Apply deny-by-exception (blacklist) / permit-by-exception (whitelist).",
       ["application_allowlist", "app_control"], ["AppLocker", "WDAC"],
       "Deploy application allow-listing on endpoints/servers."),
    _c("3.4.9", "CM", 1, "Control and monitor user-installed software.",
       ["software_install_control"], ["Intune", "AppLocker"],
       "Restrict user software installation; monitor installs."),

    # --- 3.5 Identification and Authentication (IA) — 11 controls ---
    _c("3.5.1", "IA", 5, "Identify system users, processes, and devices.",
       ["identity_management", "iam"], ["Azure AD", "Okta"],
       "Maintain a unique identity for every user/device/process."),
    _c("3.5.2", "IA", 5, "Authenticate identities before allowing access.",
       ["authentication", "iam"], ["Azure AD"],
       "Authenticate all identities prior to access."),
    _c("3.5.3", "IA", 5, "Use multifactor authentication for privileged + network access.",
       ["mfa", "multifactor"], ["Azure AD MFA", "Duo", "Okta"],
       "Enforce MFA for all privileged and network/remote access."),
    _c("3.5.4", "IA", 1, "Employ replay-resistant authentication for network access.",
       ["replay_resistant_auth", "mfa"], ["Kerberos", "FIDO2"],
       "Use replay-resistant mechanisms (FIDO2/Kerberos/TLS)."),
    _c("3.5.5", "IA", 1, "Prevent reuse of identifiers for a defined period.",
       ["identifier_reuse_policy"], [],
       "Prohibit identifier reuse for a defined retention period."),
    _c("3.5.6", "IA", 1, "Disable identifiers after a period of inactivity.",
       ["inactive_account_disable"], ["Azure AD"],
       "Auto-disable accounts after inactivity (e.g. 45 days)."),
    _c("3.5.7", "IA", 1, "Enforce minimum password complexity / change of characters.",
       ["password_policy"], ["Azure AD", "GPO"],
       "Set password complexity per current NIST 800-63B guidance."),
    _c("3.5.8", "IA", 1, "Prohibit password reuse for a number of generations.",
       ["password_history"], ["GPO"],
       "Enforce password history (e.g. 24 generations)."),
    _c("3.5.9", "IA", 1, "Allow temporary password use with immediate change.",
       ["temp_password_policy"], [],
       "Force change of temporary passwords at first logon."),
    _c("3.5.10", "IA", 5, "Store and transmit only cryptographically-protected passwords.",
       ["password_hashing", "credential_protection"], [],
       "Hash/salt stored credentials; never transmit cleartext."),
    _c("3.5.11", "IA", 1, "Obscure feedback of authentication information.",
       ["auth_feedback_obscured"], [],
       "Mask password entry and authentication feedback."),

    # --- 3.6 Incident Response (IR) — 3 controls ---
    _c("3.6.1", "IR", 5, "Establish an operational incident-handling capability.",
       ["incident_response_plan", "ir_plan"], [],
       "Stand up an IR capability: prep, detect, contain, recover."),
    _c("3.6.2", "IR", 5, "Track, document, and report incidents to designated officials.",
       ["incident_reporting"], [],
       "Document incidents; report per DFARS 72-hour rule (DIBNet)."),
    _c("3.6.3", "IR", 1, "Test the incident response capability.",
       ["ir_tabletop", "ir_testing"], [],
       "Run periodic IR tabletop / functional exercises."),

    # --- 3.7 Maintenance (MA) — 6 controls ---
    _c("3.7.1", "MA", 3, "Perform maintenance on organizational systems.",
       ["maintenance_program"], [],
       "Maintain a scheduled, documented maintenance program."),
    _c("3.7.2", "MA", 5, "Control tools, techniques, mechanisms, and personnel for maintenance.",
       ["maintenance_controls"], [],
       "Control and inventory maintenance tools and access."),
    _c("3.7.3", "MA", 1, "Sanitize equipment removed for off-site maintenance.",
       ["media_sanitization", "offsite_maint_sanitize"], [],
       "Sanitize CUI from equipment before off-site maintenance."),
    _c("3.7.4", "MA", 3, "Check media containing diagnostic/test programs for malicious code.",
       ["maint_media_scan", "antivirus"], [],
       "Scan diagnostic/test media for malware before use."),
    _c("3.7.5", "MA", 5, "Require MFA for nonlocal maintenance sessions.",
       ["nonlocal_maint_mfa", "mfa"], [],
       "Require MFA + session termination for remote maintenance."),
    _c("3.7.6", "MA", 1, "Supervise maintenance activities of personnel without access.",
       ["maint_supervision"], [],
       "Escort/supervise uncleared maintenance personnel."),

    # --- 3.8 Media Protection (MP) — 9 controls ---
    _c("3.8.1", "MP", 3, "Protect (physically) system media containing CUI.",
       ["media_physical_protection"], [],
       "Store CUI media in controlled, lockable locations."),
    _c("3.8.2", "MP", 3, "Limit access to CUI on system media to authorized users.",
       ["media_access_control"], [],
       "Restrict access to CUI-bearing media to authorized users."),
    _c("3.8.3", "MP", 5, "Sanitize or destroy media containing CUI before disposal/reuse.",
       ["media_sanitization"], [],
       "Sanitize/destroy media per NIST SP 800-88 before reuse."),
    _c("3.8.4", "MP", 1, "Mark media with necessary CUI markings and distribution limits.",
       ["media_marking", "cui_marking"], [],
       "Apply CUI banner markings and distribution limits to media."),
    _c("3.8.5", "MP", 1, "Control access to media during transport outside controlled areas.",
       ["media_transport_control"], [],
       "Control/track CUI media in transit."),
    _c("3.8.6", "MP", 1, "Use cryptography to protect CUI on digital media in transport.",
       ["media_transport_encryption", "fips_crypto"], [],
       "Encrypt CUI on transported digital media (FIPS-validated)."),
    _c("3.8.7", "MP", 5, "Control the use of removable media on system components.",
       ["removable_media_control", "usb_control"], ["Intune"],
       "Restrict/monitor removable media usage."),
    _c("3.8.8", "MP", 3, "Prohibit use of portable storage with no identifiable owner.",
       ["ownerless_media_prohibition"], [],
       "Block portable storage with no identifiable owner."),
    _c("3.8.9", "MP", 1, "Protect confidentiality of backup CUI at storage locations.",
       ["backup_encryption", "backup"], ["AWS Backup", "Veeam"],
       "Encrypt and access-control CUI backups."),

    # --- 3.9 Personnel Security (PS) — 2 controls ---
    _c("3.9.1", "PS", 3, "Screen individuals prior to authorizing access to CUI.",
       ["personnel_screening"], [],
       "Conduct background screening before granting CUI access."),
    _c("3.9.2", "PS", 5, "Protect CUI during/after personnel actions (termination/transfer).",
       ["offboarding_process"], [],
       "Revoke access and recover assets on termination/transfer."),

    # --- 3.10 Physical Protection (PE) — 6 controls ---
    _c("3.10.1", "PE", 5, "Limit physical access to systems, equipment, and environments.",
       ["physical_access_control"], [],
       "Control physical access to facilities housing CUI systems."),
    _c("3.10.2", "PE", 1, "Protect and monitor the physical facility and infrastructure.",
       ["facility_monitoring"], [],
       "Monitor facility access (badging, cameras)."),
    _c("3.10.3", "PE", 1, "Escort visitors and monitor visitor activity.",
       ["visitor_control"], [],
       "Escort and log all visitors in CUI areas."),
    _c("3.10.4", "PE", 1, "Maintain audit logs of physical access.",
       ["physical_access_logs"], [],
       "Retain physical access logs (badge/visitor)."),
    _c("3.10.5", "PE", 1, "Control and manage physical access devices.",
       ["access_device_management"], [],
       "Inventory and manage keys/badges/combinations."),
    _c("3.10.6", "PE", 3, "Enforce safeguarding measures for CUI at alternate work sites.",
       ["remote_work_safeguards"], [],
       "Define safeguards for CUI at telework/alternate sites."),

    # --- 3.11 Risk Assessment (RA) — 3 controls ---
    _c("3.11.1", "RA", 3, "Periodically assess risk to operations, assets, and individuals.",
       ["risk_assessment"], [],
       "Conduct and document periodic risk assessments."),
    _c("3.11.2", "RA", 5, "Scan for vulnerabilities periodically and when new ones identified.",
       ["vulnerability_scanning", "vuln_scan"], ["Nessus", "Qualys", "AWS Inspector"],
       "Run authenticated vulnerability scans on a schedule."),
    _c("3.11.3", "RA", 1, "Remediate vulnerabilities in accordance with risk assessments.",
       ["vulnerability_remediation", "patch_management"], [],
       "Track and remediate findings per risk-based SLAs."),

    # --- 3.12 Security Assessment (CA) — 4 controls ---
    _c("3.12.1", "CA", 5, "Periodically assess security controls for effectiveness.",
       ["control_assessment"], [],
       "Assess control effectiveness periodically."),
    _c("3.12.2", "CA", 3, "Develop/implement plans of action to correct deficiencies.",
       ["poam"], [],
       "Maintain a POA&M for all open deficiencies."),
    _c("3.12.3", "CA", 5, "Monitor security controls on an ongoing basis.",
       ["continuous_monitoring", "siem"], ["AWS Config", "Sentinel"],
       "Implement continuous control monitoring."),
    _c("3.12.4", "CA", 0, "Develop, document, and update System Security Plans (SSP).",
       ["ssp"], [],
       "Maintain a current System Security Plan (no point value)."),

    # --- 3.13 System and Communications Protection (SC) — 16 controls ---
    _c("3.13.1", "SC", 5, "Monitor/control/protect communications at boundaries.",
       ["firewall", "boundary_protection"], ["AWS Security Groups", "Palo Alto"],
       "Deploy boundary firewalls and monitor external connections."),
    _c("3.13.2", "SC", 5, "Employ architectural designs/techniques that promote security.",
       ["secure_architecture"], [],
       "Apply secure design principles (defense-in-depth)."),
    _c("3.13.3", "SC", 1, "Separate user functionality from system management functionality.",
       ["management_plane_separation"], [],
       "Isolate management interfaces from user functionality."),
    _c("3.13.4", "SC", 1, "Prevent unauthorized/unintended information transfer via shared resources.",
       ["shared_resource_isolation"], [],
       "Prevent residual data leakage across shared resources."),
    _c("3.13.5", "SC", 5, "Implement subnetworks for publicly accessible components (DMZ).",
       ["dmz", "network_segmentation"], ["AWS VPC", "Azure VNet"],
       "Place public-facing components in a separate DMZ subnet."),
    _c("3.13.6", "SC", 5, "Deny network traffic by default; allow by exception.",
       ["default_deny", "firewall"], [],
       "Configure firewalls/security groups to deny-by-default."),
    _c("3.13.7", "SC", 1, "Prevent split tunneling for remote devices.",
       ["split_tunnel_prevention", "vpn"], [],
       "Disable split tunneling on the VPN client."),
    _c("3.13.8", "SC", 3, "Use cryptography to protect CUI in transit unless otherwise protected.",
       ["tls", "transit_encryption", "fips_crypto"], [],
       "Encrypt CUI in transit with FIPS-validated TLS."),
    _c("3.13.9", "SC", 1, "Terminate network connections at end of session or after inactivity.",
       ["connection_termination"], [],
       "Terminate idle/expired network connections."),
    _c("3.13.10", "SC", 1, "Establish/manage cryptographic keys.",
       ["key_management", "kms"], ["AWS KMS", "Azure Key Vault"],
       "Use a managed key store with rotation and access control."),
    _c("3.13.11", "SC", 5, "Employ FIPS-validated cryptography to protect CUI.",
       ["fips_crypto", "fips_140"], ["AWS KMS (FIPS)", "BitLocker (FIPS)"],
       "Use only FIPS 140-2/3 validated cryptographic modules."),
    _c("3.13.12", "SC", 1, "Prohibit remote activation of collaborative devices; indicate use.",
       ["collaborative_device_control"], [],
       "Disable remote activation of cameras/mics; indicate use."),
    _c("3.13.13", "SC", 1, "Control and monitor use of mobile code.",
       ["mobile_code_control"], [],
       "Restrict and monitor mobile code (Java/ActiveX/scripts)."),
    _c("3.13.14", "SC", 1, "Control and monitor use of Voice over IP (VoIP).",
       ["voip_control"], [],
       "Control and monitor VoIP usage."),
    _c("3.13.15", "SC", 5, "Protect authenticity of communications sessions.",
       ["session_authenticity", "tls"], [],
       "Protect session authenticity (TLS, signed tokens)."),
    _c("3.13.16", "SC", 3, "Protect confidentiality of CUI at rest.",
       ["encryption_at_rest", "disk_encryption", "fips_crypto"],
       ["AWS EBS encryption", "BitLocker"],
       "Encrypt CUI at rest with FIPS-validated mechanisms."),

    # --- 3.14 System and Information Integrity (SI) — 7 controls ---
    _c("3.14.1", "SI", 5, "Identify, report, and correct system flaws in a timely manner.",
       ["patch_management", "flaw_remediation"], ["WSUS", "Intune"],
       "Run a timely patch/flaw-remediation program."),
    _c("3.14.2", "SI", 5, "Provide protection from malicious code at appropriate locations.",
       ["antivirus", "edr", "endpoint_protection"], ["Defender", "CrowdStrike"],
       "Deploy EDR/anti-malware on endpoints and servers."),
    _c("3.14.3", "SI", 5, "Monitor system security alerts/advisories and take action.",
       ["security_alert_monitoring", "threat_intel"], [],
       "Subscribe to advisories (CISA/US-CERT) and act on them."),
    _c("3.14.4", "SI", 1, "Update malicious code protection mechanisms.",
       ["av_signature_updates", "antivirus"], ["Defender", "CrowdStrike"],
       "Keep anti-malware definitions/engines current."),
    _c("3.14.5", "SI", 3, "Perform periodic and real-time scans of files from external sources.",
       ["realtime_scanning", "antivirus"], ["Defender"],
       "Enable real-time + scheduled malware scans."),
    _c("3.14.6", "SI", 5, "Monitor systems/communications to detect attacks and indicators.",
       ["ids", "ips", "network_monitoring", "edr"], ["GuardDuty", "Sentinel"],
       "Deploy IDS/IPS + network/endpoint monitoring."),
    _c("3.14.7", "SI", 3, "Identify unauthorized use of organizational systems.",
       ["unauthorized_use_detection", "siem"], ["Sentinel", "Splunk"],
       "Detect and alert on unauthorized system use."),
]


# Index for fast lookup.
_BY_ID: Dict[str, Control] = {c.id: c for c in CATALOG}


def list_controls(family: Optional[str] = None) -> List[Control]:
    """Return catalog controls, optionally filtered to one family abbrev."""
    if family is None:
        return list(CATALOG)
    fam = family.upper()
    return [c for c in CATALOG if c.family == fam]


def get_control(cid: str) -> Optional[Control]:
    return _BY_ID.get(cid)


# ---------------------------------------------------------------------------
# Stack-aware gap assessment.
# ---------------------------------------------------------------------------
def _key_truthy(inventory: Dict, key: str) -> bool:
    """Treat a key as satisfied if present and truthy (bool/str/non-empty)."""
    if key not in inventory:
        return False
    v = inventory[key]
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() not in ("", "no", "false", "0", "none", "planned", "partial")
    if isinstance(v, (list, dict)):
        return len(v) > 0
    if v is None:
        return False
    return bool(v)


def _key_partial(inventory: Dict, key: str) -> bool:
    """A value of 'planned'/'partial' marks a partial implementation."""
    v = inventory.get(key)
    return isinstance(v, str) and v.strip().lower() in ("planned", "partial", "in_progress")


def assess(inventory: Dict, family: Optional[str] = None) -> List[GapFinding]:
    """Assess every catalog control against a stack/inventory description.

    `inventory` is a flat dict of evidence keys -> truthy/str/list values, plus
    optional special keys:
      - "platforms": list of platform names already in use (e.g. ["AWS GovCloud"])
      - "na": list of control ids that are not applicable to this system.

    Returns one GapFinding per control with an inferred Status. Controls with
    no matching evidence keys in the inventory are UNKNOWN (insufficient data);
    controls whose evidence is present are MET; partial markers -> PARTIAL;
    everything required but absent (when at least one related key exists) ->
    NOT_MET.
    """
    inv = dict(inventory or {})
    platforms = {str(p).strip() for p in inv.get("platforms", []) if str(p).strip()}
    na_ids = {str(x).strip() for x in inv.get("na", [])}

    controls = list_controls(family)
    findings: List[GapFinding] = []

    for c in controls:
        inherited_hint = ""
        if c.inherited_from and platforms:
            shared = [p for p in c.inherited_from
                      if any(p.lower().split(" (")[0] in pl.lower() or pl.lower() in p.lower()
                             for pl in platforms)]
            if shared:
                inherited_hint = "Likely inherited from: " + ", ".join(shared)

        if c.id in na_ids:
            findings.append(GapFinding(
                c.id, c.family, c.weight, Status.NA, c.title,
                "Marked not-applicable by system owner.", c.remediation, inherited_hint))
            continue

        # Evaluate evidence keys.
        present = [k for k in c.evidence_keys if _key_truthy(inv, k)]
        partial = [k for k in c.evidence_keys if _key_partial(inv, k)]
        mentioned = [k for k in c.evidence_keys if k in inv]

        if not c.evidence_keys:
            # No machine-checkable evidence (policy/process control).
            status = Status.UNKNOWN
            rationale = "Policy/process control; verify with documentation."
        elif present:
            status = Status.MET
            rationale = "Evidence present: " + ", ".join(present)
        elif partial:
            status = Status.PARTIAL
            rationale = "Partially implemented / planned: " + ", ".join(partial)
        elif mentioned:
            status = Status.NOT_MET
            rationale = ("Evidence keys present but not satisfied: "
                         + ", ".join(mentioned))
        elif inherited_hint:
            status = Status.PARTIAL
            rationale = "No local evidence; may be inherited from platform."
        else:
            status = Status.UNKNOWN
            rationale = ("No inventory evidence for keys: "
                         + ", ".join(c.evidence_keys))

        findings.append(GapFinding(
            c.id, c.family, c.weight, status, c.title, rationale,
            c.remediation, inherited_hint))

    return findings


# ---------------------------------------------------------------------------
# SPRS-style scoring (DoD Assessment Methodology).
# Start at 110. Subtract each control's weight when NOT met. PARTIAL on the few
# "implement OR have a policy" controls earns partial credit per the methodology
# subtraction-of-half rule for 3.5.3 and 3.13.11; we keep it simple and treat
# PARTIAL as half the weight deducted.
# ---------------------------------------------------------------------------
def score_sprs(findings: List[GapFinding]) -> dict:
    max_score = 110
    deduction = 0
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
        if f.status == Status.NOT_MET or f.status == Status.UNKNOWN:
            deduction += f.weight
        elif f.status == Status.PARTIAL:
            # Half credit (round up the deduction).
            deduction += (f.weight + 1) // 2
    score = max_score - deduction
    # SPRS allows scores down to -203 (sum of all weights exceeds 110).
    return {
        "max_score": max_score,
        "deduction": deduction,
        "sprs_score": score,
        "counts": counts,
        "assessed_controls": len(findings),
        "perfect_score_possible": max_score,
    }


# ---------------------------------------------------------------------------
# SSP skeleton + POA&M generation.
# ---------------------------------------------------------------------------
def build_ssp(inventory: Dict, findings: List[GapFinding],
              system_name: str = "Information System") -> str:
    """Produce a System Security Plan skeleton (Markdown) per NIST 800-171 §3.12.4."""
    score = score_sprs(findings)
    inv = dict(inventory or {})
    platforms = inv.get("platforms", [])
    lines: List[str] = []
    a = lines.append
    a(f"# System Security Plan (SSP) — {system_name}")
    a("")
    a(f"_Generated by {TOOL_NAME} {TOOL_VERSION} — NIST SP 800-171 Rev. 2 (CMMC Level 2)_")
    a("")
    a("## 1. System Identification")
    a(f"- **System name:** {system_name}")
    a(f"- **Platforms / boundary:** {', '.join(map(str, platforms)) or 'TODO: define authorization boundary'}")
    a(f"- **Controls assessed:** {score['assessed_controls']} of 110")
    a("- **CUI categories handled:** TODO (e.g. CTI, ITAR, Export-Controlled)")
    a("- **System owner / ISSO:** TODO")
    a("")
    a("## 2. SPRS Self-Assessment Score")
    a(f"- **Score:** {score['sprs_score']} / {score['max_score']}")
    a(f"- **Point deduction:** {score['deduction']}")
    c = score["counts"]
    a(f"- **MET:** {c['MET']}  **PARTIAL:** {c['PARTIAL']}  "
      f"**NOT_MET:** {c['NOT_MET']}  **NA:** {c['NA']}  **UNKNOWN:** {c['UNKNOWN']}")
    a("")
    a("## 3. Control Implementation by Family")
    for fam_abbr, fam_name in FAMILIES.items():
        fam_findings = [f for f in findings if f.family == fam_abbr]
        if not fam_findings:
            continue
        a("")
        a(f"### 3.{fam_abbr} — {fam_name} ({len(fam_findings)} controls)")
        a("")
        a("| Control | Status | Requirement | Implementation / Notes |")
        a("|---------|--------|-------------|------------------------|")
        for f in fam_findings:
            note = f.rationale
            if f.inherited_hint:
                note += f" — {f.inherited_hint}"
            a(f"| {f.control} | {f.status.value} | {f.title} | {note} |")
    a("")
    a("## 4. Plan of Action & Milestones (POA&M)")
    a("See companion POA&M for all PARTIAL / NOT_MET / UNKNOWN controls.")
    a("")
    return "\n".join(lines)


def build_poam(findings: List[GapFinding]) -> List[dict]:
    """Return POA&M rows for every control that is not fully MET/NA."""
    rows: List[dict] = []
    open_findings = [f for f in findings
                     if f.status in (Status.NOT_MET, Status.PARTIAL, Status.UNKNOWN)]
    # Order: by point weight (highest impact first), then control id.
    open_findings.sort(key=lambda f: (-f.weight, f.control))
    for i, f in enumerate(open_findings, 1):
        rows.append({
            "item": i,
            "control": f.control,
            "family": f.family,
            "weight": f.weight,
            "status": f.status.value,
            "weakness": f.title,
            "finding": f.rationale,
            "remediation": f.remediation,
            "inherited_hint": f.inherited_hint,
            "milestone": "TODO: target date",
            "resources": "TODO: owner / budget",
        })
    return rows


# ---------------------------------------------------------------------------
# Renderers.
# ---------------------------------------------------------------------------
def has_findings(findings: List[GapFinding]) -> bool:
    return any(f.status in FAIL_STATUSES for f in findings)


def render_json(findings: List[GapFinding], inventory: Optional[Dict] = None,
                system_name: str = "Information System",
                include_ssp: bool = False) -> str:
    out = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "framework": "NIST SP 800-171 Rev. 2 / CMMC Level 2",
        "system_name": system_name,
        "score": score_sprs(findings),
        "findings": [f.to_dict() for f in findings],
        "poam": build_poam(findings),
    }
    if include_ssp:
        out["ssp"] = build_ssp(inventory or {}, findings, system_name)
    return json.dumps(out, indent=2)


def render_table(findings: List[GapFinding], system_name: str = "Information System") -> str:
    score = score_sprs(findings)
    lines: List[str] = []
    a = lines.append
    a(f"{TOOL_NAME} {TOOL_VERSION} — NIST SP 800-171 / CMMC Level 2 assessment")
    a(f"System: {system_name}")
    a("=" * 72)
    a(f"  SPRS score: {score['sprs_score']} / {score['max_score']}  "
      f"(deduction {score['deduction']})")
    c = score["counts"]
    a(f"  MET {c['MET']}  PARTIAL {c['PARTIAL']}  NOT_MET {c['NOT_MET']}  "
      f"NA {c['NA']}  UNKNOWN {c['UNKNOWN']}")
    a("=" * 72)
    cur_fam = None
    for f in sorted(findings, key=lambda x: (x.family, x.control)):
        if f.family != cur_fam:
            cur_fam = f.family
            a("")
            a(f"[{f.family}] {FAMILIES.get(f.family, f.family)}")
            a("-" * 72)
        flag = "  " if f.status in (Status.MET, Status.NA) else "->"
        a(f" {flag} {f.control:<8} {f.status.value:<8} (w{f.weight}) {f.title}")
        if f.status in FAIL_STATUSES or f.status == Status.UNKNOWN:
            a(f"        {f.rationale}")
            if f.remediation:
                a(f"        FIX: {f.remediation}")
            if f.inherited_hint:
                a(f"        {f.inherited_hint}")
    a("")
    n_open = c["NOT_MET"] + c["PARTIAL"] + c["UNKNOWN"]
    a(f"{n_open} control(s) need attention (see POA&M).")
    return "\n".join(lines)
