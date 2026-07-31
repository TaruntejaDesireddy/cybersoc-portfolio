# cybersoc-portfolio

Personal Microsoft Sentinel SOC lab — deployed and configured end-to-end from scratch to close hands-on gaps (Sentinel deployment, connector configuration, SOAR automation) alongside 4+ years of SOC L2/L3 analyst experience.

## Architecture

- **Log Analytics workspace** (`law-soc-lab`) with Microsoft Sentinel enabled — 90-day retention (free tier via Sentinel), 1 GB/day ingestion cap for cost control
- **Data connectors**: Azure Activity Log, Entra ID sign-in/audit logs, Syslog (dedicated Ubuntu VM running Azure Monitor Agent, filtered via a custom Data Collection Rule to security-relevant facilities/severities only), and a custom threat intel pipeline pulling AbuseIPDB's high-confidence IP blacklist into Sentinel Threat Intelligence
- **RBAC tiering**: owner account (Sentinel Contributor), 3 simulated Tier-1 analyst accounts (Sentinel Reader — view incidents/hunt/workbooks, no write access)

## Analytics Rules (`/analytics-rules`)

60 custom-authored scheduled rules — no gallery templates. Every rule was written against a table confirmed to be ingesting in this workspace, because a rule that cannot fire is worse than no rule: it creates the appearance of coverage.

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

Logic App workflow definitions, exported as ARM templates. Secrets (API keys) are parameterized — supply your own value at deployment time, never committed. All three authenticate via system-assigned Managed Identity — no stored Azure credentials in any workflow.

| Playbook | Trigger | Purpose |
|---|---|---|
| `la-ip-enrichment.json` | HTTP (called from Sentinel incident) | Looks up an incident IP via VirusTotal, posts enrichment (malicious/suspicious/harmless counts, ASN owner, country) as an incident comment |
| `la-user-containment.json` | HTTP (called from Sentinel incident) | On High-severity incidents, disables the associated Entra ID user account via Microsoft Graph, then comments on the incident. Managed Identity scoped to `User.EnableDisableAccount.All` + `User.Read.All` only — no standing `User.ReadWrite.All` |
| `la-email-alert.json` | HTTP (called from Sentinel incident) | Sends a formatted incident alert email via Azure Communication Services Email (Azure-native, no third-party mail provider), then comments on the incident |

## Deploying

```
az deployment group create --resource-group <rg> --template-file playbooks/la-ip-enrichment.json --parameters VirusTotalApiKey=<your-key>
az deployment group create --resource-group <rg> --template-file playbooks/la-user-containment.json
az deployment group create --resource-group <rg> --template-file playbooks/la-email-alert.json
```

After deployment, grant each playbook's Managed Identity `Microsoft Sentinel Contributor` on your workspace, and (for containment) the Graph app roles above.

Analytics rules deploy from their JSON definitions:

```
./deploy-rules.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

Add `-WhatIf` to preview without writing. Each rule carries a fixed GUID, so the script is idempotent — re-running updates in place rather than creating duplicates.
