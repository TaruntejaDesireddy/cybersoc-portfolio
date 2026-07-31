# cybersoc-portfolio

Personal Microsoft Sentinel SOC lab — deployed and configured end-to-end from scratch to close hands-on gaps (Sentinel deployment, connector configuration, SOAR automation) alongside 4+ years of SOC L2/L3 analyst experience.

## Architecture

- **Log Analytics workspace** (`law-soc-lab`) with Microsoft Sentinel enabled — 90-day retention (free tier via Sentinel), 1 GB/day ingestion cap for cost control
- **Data connectors**: Azure Activity Log, Entra ID sign-in/audit logs, Syslog (dedicated Ubuntu VM running Azure Monitor Agent, filtered via a custom Data Collection Rule to security-relevant facilities/severities only), and a custom threat intel pipeline pulling AbuseIPDB's high-confidence IP blacklist into Sentinel Threat Intelligence
- **RBAC tiering**: owner account (Sentinel Contributor), 3 simulated Tier-1 analyst accounts (Sentinel Reader — view incidents/hunt/workbooks, no write access)

## Analytics Rules (`/analytics-rules`)

4 scheduled rules enabled, chosen to match the connectors actually deployed (not a generic template dump):

| Rule | Severity | MITRE ATT&CK | Data source |
|---|---|---|---|
| TI Map IP Entity to AzureActivity | Medium | Command and Control — T1071 | Threat Intelligence + Azure Activity |
| Failed logon attempts in authpriv | Medium | Credential Access — T1110 | Syslog |
| Authentication Attempt from New Country | Medium | Initial Access — T1078 | Entra ID sign-in logs |
| Suspicious resource creation/deployment | Medium | Impact — T1496 | Azure Activity |

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

Analytics rule KQL is in `/analytics-rules` with MITRE mapping headers — deploy via the Sentinel portal, `az rest` against `Microsoft.SecurityInsights/alertRules`, or as ARM/Bicep.
