# cybersoc-portfolio

Personal Microsoft Sentinel SOC lab — deployed and configured end-to-end from scratch to close hands-on gaps (Sentinel deployment, connector configuration, SOAR automation) alongside 4+ years of SOC L2/L3 analyst experience.

## Architecture

- **Log Analytics workspace** (`law-soc-lab`) with Microsoft Sentinel enabled — 90-day retention (free tier via Sentinel), 1 GB/day ingestion cap for cost control
- **Data connectors**: Azure Activity Log, Entra ID sign-in/audit logs, Syslog (dedicated Ubuntu VM running Azure Monitor Agent, filtered via a custom Data Collection Rule to security-relevant facilities/severities only), and a custom threat intel pipeline pulling AbuseIPDB's high-confidence IP blacklist into Sentinel Threat Intelligence
- **RBAC tiering**: owner account (Sentinel Contributor), 3 simulated Tier-1 analyst accounts (Sentinel Reader — view incidents/hunt/workbooks, no write access)

## Analytics Rules (`/analytics-rules`)

64 custom-authored scheduled rules — no gallery templates. Every rule was written against a table confirmed to be ingesting in this workspace, because a rule that cannot fire is worse than no rule: it creates the appearance of coverage.

| Category | Rules | Data source |
|---|---:|---|
| Azure control plane | 20 | AzureActivity |
| Identity and authentication | 20 | SigninLogs, AADNonInteractiveUserSignInLogs |
| Entra ID directory | 12 | AuditLogs |
| Linux endpoint | 5 | Syslog |
| Detection health and correlation | 3 | Heartbeat, Usage, AzureActivity |

30 High, 25 Medium, 5 Low. Entity mappings on 59 of 60, custom details on all 60, and dynamic alert titles on 44 so incident names carry the actual user, IP, or resource rather than a static string.

Each rule description documents its own detection logic, MITRE mapping, numbered triage steps, known false positives with the specific tuning lever, and source table — so triage does not depend on tribal knowledge.

See [`analytics-rules/README.md`](analytics-rules/README.md) for the full index and the three rules that need environment-specific tuning before production use.

## Playbooks (`/playbooks`)

Logic App workflow definitions, exported as ARM templates. API keys live in Azure Key Vault and are read at runtime via the playbook's system-assigned Managed Identity — never passed as deployment parameters, never stored in the workflow itself. Where a credential does transit an action, `runtimeConfiguration.secureData` masks it so it cannot be recovered from run history.

| Playbook | Trigger | Purpose | Status |
|---|---|---|---|
| `la-ip-enrichment.json` | HTTP (called from Sentinel incident) | Multi-source IP enrichment — queries both VirusTotal and AlienVault OTX in parallel, posts a combined summary (engine detection counts, threat-pulse count, reputation, ASN) as an incident comment. Each source degrades independently: if one is rate-limited or errors, the comment still posts with the other source's data rather than failing outright. | Live |
| `la-user-containment.json` | HTTP (called from Sentinel incident) | On High-severity incidents, posts an incident comment recommending the associated account be disabled. Does **not** disable the account itself. | Live |
| `la-incident-report.json` | HTTP request | Queries `SecurityIncident` joined to its underlying alerts, renders a styled HTML digest, and emails it with the full report attached. **Has no Recurrence trigger — it only runs when invoked.** See the note in the file header. | Live |
| `la-ti-abuseipdb.json` | Recurrence, daily 06:00 | Pulls the AbuseIPDB blacklist and publishes each address as a STIX 2.1 indicator through the Sentinel threat-intelligence upload API, chunked to the API's 100-object limit. Indicators carry a 7-day `valid_until` because reputation data decays. | Live |

One deliberate exception to the managed-identity rule: `la-incident-report` uses the Azure Communication Services email connector, which offers no managed-identity authentication, so it depends on an authorised API connection named `acsemail`. Every other playbook here uses plain HTTP actions with `ManagedServiceIdentity` auth and creates no API connection resources at all — which also means no interactive OAuth consent step at deploy time.

### Why the containment playbook recommends rather than acts

The first version of this playbook disabled the Entra ID account directly via `PATCH /users/{id}` over Microsoft Graph. That requires the `User.ReadWrite.All` application permission: unattended, tenant-wide, and capable of modifying *any* user, not just the one named in the incident. A single false-positive High-severity incident — not a rare event in an under-tuned environment — would silently lock out a real user with no human in the loop.

The playbook now posts a clear, actionable recommendation and stops. A human approves the actual containment action. This trades a small amount of automation for removing a standing, broad-scope Graph grant from an unattended identity — the kind of tradeoff a mature SOC makes deliberately rather than defaulting to "automate everything."

## Deploying

Prerequisite: an Azure Key Vault holding secrets `VirusTotalApiKey`, `OTXApiKey`, and `AbuseIPDBApiKey`, with `Key Vault Secrets User` granted to whichever principals will run `la-ip-enrichment` and `la-ti-abuseipdb`.

Replace every `<placeholder>` in the JSON before deploying — the committed files carry no tenant-specific values.

```bash
az deployment group create --resource-group <rg> --template-file playbooks/la-ip-enrichment.json --parameters KeyVaultName=<your-vault-name>
az deployment group create --resource-group <rg> --template-file playbooks/la-user-containment.json
az deployment group create --resource-group <rg> --template-file playbooks/la-ti-abuseipdb.json
az deployment group create --resource-group <rg> --template-file playbooks/la-incident-report.json
```

After deployment:

1. Enable each Logic App's system-assigned managed identity
2. Grant `la-ip-enrichment` and `la-ti-abuseipdb` `Key Vault Secrets User` on your vault
3. Grant every playbook's identity `Microsoft Sentinel Contributor` on your workspace (needed to post incident comments)
4. For `la-ti-abuseipdb`, that Sentinel Contributor grant **must be at workspace scope** — the threat-intelligence upload API rejects an identity that holds the role only at resource-group scope
5. For `la-incident-report`, create and authorise an ACS email API connection named `acsemail` in the same resource group, with a verified sender domain

No Graph permissions are required by any playbook in this repo.

Analytics rules deploy from their JSON definitions:

```bash
./deploy-rules.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

Add `-WhatIf` to preview without writing. Each rule carries a fixed GUID, so the script is idempotent — re-running updates in place rather than creating duplicates.
