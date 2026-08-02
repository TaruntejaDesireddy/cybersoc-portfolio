# Microsoft Sentinel Analytics Rules

64 custom-authored scheduled analytics rules for Microsoft Sentinel. No gallery templates - every rule is written against tables confirmed to be ingesting in the target workspace, with entity mappings, custom details, and dynamic alert titles.

## Design principles

**Every rule targets live data.** Rules were authored only after confirming the source table was actually ingesting. A rule that cannot fire is worse than no rule, because it creates the appearance of coverage.

**Every rule documents its own triage.** Each description carries a fixed structure - what it detects, why it matters with the MITRE technique, numbered triage steps, known false positives with the specific tuning lever, and the source table. An analyst opening an incident at 3am should not need to ask anyone what to do next.

**Query efficiency is deliberate.** Filters lead with selective columns, `has`/`has_any` term matching is used instead of `contains`, projection happens before aggregation, and query frequency is matched to period so scan windows do not overlap and re-read the same data.

**Alerts are self-describing.** 45 of the 64 rules use `alertDetailsOverride` so the incident title names the actual user, IP, or resource involved rather than repeating a static rule name.

**Incidents group by subject, not by alert.** Every rule sets a 24-hour `groupingConfiguration` keyed on its subject entity — Account where one exists, else Host, else IP. This is deliberate and was learned the hard way: with grouping disabled, a single deleted VM produced 57 separate incidents from one condition. Note that IP is never used as a grouping key on a rule that also carries an Account or Host, because an operator behind a rotating VPN presents a different IP on every alert, which defeats grouping entirely. The two rules with no entity mappings fall back to `AnyAlert`.

## Coverage

| Category | Rules | Primary data source |
|---|---:|---|
| Azure Control Plane | 21 | AzureActivity, LAQueryLogs |
| Identity and Authentication | 21 | SigninLogs, AADNonInteractiveUserSignInLogs |
| Entra ID Directory | 12 | AuditLogs |
| Linux Endpoint | 5 | Syslog |
| Detection Health and Correlation | 5 | Heartbeat, Usage, ThreatIntelIndicators, ACSEmailStatusUpdateOperational |
| **Total** | **64** | |

Severity split: 31 High, 27 Medium, 6 Low.

Grouping keys: 53 by Account, 6 by Host, 3 by IP, 2 `AnyAlert`.


## Azure Control Plane

| Rule | Severity | MITRE | Source |
|---|---|---|---|
| [Resource Group Deleted](azure-control-plane/resource-group-deleted.json) | High | T1485 - Impact | AzureActivity |
| [Network Security Group Modified or Deleted](azure-control-plane/network-security-group-modified-or-deleted.json) | Medium | T1562 - DefenseEvasion | AzureActivity |
| [Key Vault Access Policy Modified](azure-control-plane/key-vault-access-policy-modified.json) | High | T1552 - CredentialAccess | AzureActivity |
| [Key Vault Deleted or Purged](azure-control-plane/key-vault-deleted-or-purged.json) | High | T1485 - Impact | AzureActivity |
| [Diagnostic Settings Deleted (Log Tampering)](azure-control-plane/diagnostic-settings-deleted-log-tampering.json) | High | T1562 - DefenseEvasion | AzureActivity |
| [RBAC Role Assignment Created](azure-control-plane/rbac-role-assignment-created.json) | Medium | T1098 - PrivilegeEscalation, Persistence | AzureActivity |
| [RBAC Role Assignment Removed](azure-control-plane/rbac-role-assignment-removed.json) | Medium | T1531 - DefenseEvasion, Impact | AzureActivity |
| [VM Run Command Executed](azure-control-plane/vm-run-command-executed.json) | High | T1059 - Execution | AzureActivity |
| [VM Extension Deployed](azure-control-plane/vm-extension-deployed.json) | Medium | T1059 - Execution, Persistence | AzureActivity |
| [Storage Account Keys Enumerated](azure-control-plane/storage-account-keys-enumerated.json) | Medium | T1552 - CredentialAccess, Collection | AzureActivity |
| [Storage Account Deleted](azure-control-plane/storage-account-deleted.json) | High | T1485 - Impact | AzureActivity |
| [Mass Resource Deletion Burst](azure-control-plane/mass-resource-deletion-burst.json) | High | T1485 - Impact | AzureActivity |
| [Control Plane Permission Probing (Failure Burst)](azure-control-plane/control-plane-permission-probing-failure-burst.json) | Medium | T1087 - Discovery | AzureActivity |
| [Policy Assignment Deleted](azure-control-plane/policy-assignment-deleted.json) | Medium | T1562 - DefenseEvasion | AzureActivity |
| [Sentinel Configuration Modified or Deleted](azure-control-plane/sentinel-configuration-modified-or-deleted.json) | High | T1562 - DefenseEvasion | AzureActivity |
| [Log Analytics Workspace Deleted](azure-control-plane/log-analytics-workspace-deleted.json) | High | T1485 - DefenseEvasion, Impact | AzureActivity |
| [Automation Runbook or Webhook Created or Modified](azure-control-plane/automation-runbook-or-webhook-created-or-modified.json) | Medium | T1053 - Persistence, Execution | AzureActivity |
| [Public IP Address Created](azure-control-plane/public-ip-address-created.json) | Low | T1133 - InitialAccess | AzureActivity |
| [Control Plane Activity from Previously Unseen IP](azure-control-plane/control-plane-activity-from-previously-unseen-ip.json) | Medium | T1078 - InitialAccess | AzureActivity |
| [Firewall or Bastion Modified or Deleted](azure-control-plane/firewall-or-bastion-modified-or-deleted.json) | High | T1562 - DefenseEvasion | AzureActivity |

## Identity and Authentication

| Rule | Severity | MITRE | Source |
|---|---|---|---|
| [Sign-in from Threat Intelligence Indicator IP](identity/signin-from-threat-intelligence-indicator-ip.json) | High | T1078 - InitialAccess | SigninLogs, ThreatIntelIndicators |
| [Password Spray from Single Source IP](identity/password-spray-from-single-source-ip.json) | High | T1110 - CredentialAccess | SigninLogs |
| [Brute Force Against Single Account](identity/brute-force-against-single-account.json) | Medium | T1110 - CredentialAccess | SigninLogs |
| [Successful Sign-in Following Brute Force](identity/successful-signin-following-brute-force.json) | High | T1110 - CredentialAccess, InitialAccess | SigninLogs |
| [Sign-in from Multiple Countries in Short Window](identity/signin-from-multiple-countries-in-short-window.json) | High | T1078 - InitialAccess, DefenseEvasion | SigninLogs |
| [MFA Denial Burst (Push Fatigue)](identity/mfa-denial-burst-push-fatigue.json) | High | T1621 - CredentialAccess | SigninLogs |
| [Legacy Authentication Protocol Used](identity/legacy-authentication-protocol-used.json) | Medium | T1078 - DefenseEvasion, CredentialAccess | SigninLogs |
| [Risky Sign-in Detected by Entra ID Protection](identity/risky-signin-detected-by-entra-id-protection.json) | High | T1078 - InitialAccess | SigninLogs |
| [Sign-in from Anonymous or Tor IP](identity/signin-from-anonymous-or-tor-ip.json) | High | T1078 - InitialAccess, DefenseEvasion | SigninLogs |
| [Conditional Access Block Burst](identity/conditional-access-block-burst.json) | Medium | T1562 - DefenseEvasion | SigninLogs |
| [Guest Account Successful Sign-in](identity/guest-account-successful-signin.json) | Low | T1078 - InitialAccess | SigninLogs |
| [Non-Interactive Sign-in Volume Spike](identity/noninteractive-signin-volume-spike.json) | Medium | T1078 - Persistence, Collection | AADNonInteractiveUserSignInLogs |
| [Sign-in from Country Not Seen for User](identity/signin-from-country-not-seen-for-user.json) | Medium | T1078 - InitialAccess | SigninLogs |
| [Dormant Account Reactivated](identity/dormant-account-reactivated.json) | Medium | T1078 - Persistence, InitialAccess | SigninLogs |
| [Azure Management Plane Access from New IP](identity/azure-management-plane-access-from-new-ip.json) | High | T1078 - InitialAccess, PrivilegeEscalation | SigninLogs |
| [Non-Interactive Sign-in from Threat Intelligence IP](identity/noninteractive-signin-from-threat-intelligence-ip.json) | High | T1078 - InitialAccess, Persistence | AADNonInteractiveUserSignInLogs, ThreatIntelIndicators |
| [Management Access from Non-Compliant Device](identity/management-access-from-noncompliant-device.json) | Medium | T1078 - DefenseEvasion | SigninLogs |
| [Cross-Tenant Sign-in Activity](identity/crosstenant-signin-activity.json) | Low | T1078 - InitialAccess, Collection | SigninLogs |
| [Single IP Authenticating as Many Accounts](identity/single-ip-authenticating-as-many-accounts.json) | High | T1078 - CredentialAccess, InitialAccess | SigninLogs |
| [Repeated Sign-in Attempts to Disabled or Blocked Accounts](identity/repeated-signin-attempts-to-disabled-or-blocked-accounts.json) | Medium | T1078 - InitialAccess, Persistence | SigninLogs |

## Entra ID Directory

| Rule | Severity | MITRE | Source |
|---|---|---|---|
| [Credential Added to Application or Service Principal](entra-id/credential-added-to-application-or-service-principal.json) | High | T1098 - Persistence | AuditLogs |
| [Global Administrator Role Assigned](entra-id/global-administrator-role-assigned.json) | High | T1098 - PrivilegeEscalation, Persistence | AuditLogs |
| [Privileged Role Assigned](entra-id/privileged-role-assigned.json) | Medium | T1098 - PrivilegeEscalation, Persistence | AuditLogs |
| [MFA Method Registered or Modified](entra-id/mfa-method-registered-or-modified.json) | Medium | T1556 - Persistence, DefenseEvasion | AuditLogs |
| [Conditional Access Policy Changed](entra-id/conditional-access-policy-changed.json) | High | T1562 - DefenseEvasion | AuditLogs |
| [OAuth Application Consent Granted](entra-id/oauth-application-consent-granted.json) | Medium | T1528 - CredentialAccess | AuditLogs |
| [Tenant-Wide Admin Consent Granted](entra-id/tenantwide-admin-consent-granted.json) | High | T1528 - CredentialAccess | AuditLogs |
| [External Guest User Invited](entra-id/external-guest-user-invited.json) | Low | T1136 - InitialAccess, Persistence | AuditLogs |
| [Bulk User Deletion](entra-id/bulk-user-deletion.json) | High | T1531 - Impact | AuditLogs |
| [New Account Granted Role Within One Hour](entra-id/new-account-granted-role-within-one-hour.json) | High | T1136 - PrivilegeEscalation, Persistence | AuditLogs |
| [Domain or Federation Settings Changed](entra-id/domain-or-federation-settings-changed.json) | High | T1484 - Persistence, DefenseEvasion | AuditLogs |
| [Password Reset Performed on Another User](entra-id/password-reset-performed-on-another-user.json) | Medium | T1098 - CredentialAccess, Persistence | AuditLogs |

## Linux Endpoint

| Rule | Severity | MITRE | Source |
|---|---|---|---|
| [SSH Brute Force Against Host](linux/ssh-brute-force-against-host.json) | Medium | T1110 - CredentialAccess | Syslog |
| [Successful SSH Login Following Brute Force](linux/successful-ssh-login-following-brute-force.json) | High | T1110 - CredentialAccess, InitialAccess | Syslog |
| [Sudo Privilege Escalation Failures](linux/sudo-privilege-escalation-failures.json) | Medium | T1548 - PrivilegeEscalation | Syslog |
| [User or Group Account Modified](linux/user-or-group-account-modified.json) | Medium | T1136 - Persistence | Syslog |
| [Security Logging Service Stopped](linux/security-logging-service-stopped.json) | High | T1562 - DefenseEvasion | Syslog |

## Detection Health and Correlation

| Rule | Severity | MITRE | Source |
|---|---|---|---|
| [Data Source Heartbeat Missing](detection-health/data-source-heartbeat-missing.json) | Low | T1489 - Impact | Heartbeat |
| [Log Ingestion Volume Drop by Data Type](detection-health/log-ingestion-volume-drop-by-data-type.json) | Medium | T1562 - DefenseEvasion | Usage |
| [Privilege Escalation Followed by Resource Deletion](detection-health/privilege-escalation-followed-by-resource-deletion.json) | High | T1098 - PrivilegeEscalation, Impact | AzureActivity |

## Deploying

```powershell
./deploy-rules.ps1 -SubscriptionId <sub-id> -ResourceGroup <rg> -WorkspaceName <workspace>
```

Add `-WhatIf` to list what would be deployed without writing anything. The script is idempotent - each rule is written by a fixed GUID, so re-running updates in place rather than creating duplicates.

## Tuning required before production use

Three rules will not be usable as-is in most environments. Each states this in its own description:

- **Single IP Authenticating as Many Accounts** - needs your NAT and VPN egress addresses excluded, or it will fire on every corporate gateway.
- **Non-Interactive Sign-in Volume Spike** - the threshold of 200 is a placeholder. Measure your own p95 before enabling.
- **Privilege Escalation Followed by Resource Deletion** - any CI/CD pipeline that grants permissions then tears down infrastructure matches this exactly. Exclude deployment service principals first.

Baseline rules (previously unseen IP, new country, dormant account) compare against a trailing 14-day window and will be noisy for their first two weeks while that baseline populates.


