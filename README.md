# cybersoc-portfolio

KQL detection rules, hunt packages, and SOAR playbook ARM templates from my personal Microsoft Sentinel lab. Built to close hands-on gaps in Sentinel deployment, connector configuration, and SOAR automation alongside 4+ years of SOC L2/L3 analyst experience.

## Playbooks (`/playbooks`)

Logic App workflow definitions, exported as ARM templates. Secrets (API keys) are parameterized — supply your own value at deployment time, never committed.

| Playbook | Trigger | Purpose |
|---|---|---|
| `la-ip-enrichment.json` | HTTP (called from Sentinel incident) | Looks up an incident IP via VirusTotal, posts enrichment (malicious/suspicious/harmless counts, ASN owner, country) as an incident comment |
| `la-user-containment.json` | HTTP (called from Sentinel incident) | On High-severity incidents, disables the associated Entra ID user account via Microsoft Graph, then comments on the incident. Uses a system-assigned Managed Identity scoped to `User.EnableDisableAccount.All` + `User.Read.All` only — no standing `User.ReadWrite.All` |

Both playbooks authenticate to Azure Resource Manager and Microsoft Graph via system-assigned Managed Identity — no stored Azure credentials in either workflow.

## Deploying

```
az deployment group create --resource-group <rg> --template-file playbooks/la-ip-enrichment.json --parameters VirusTotalApiKey=<your-key>
az deployment group create --resource-group <rg> --template-file playbooks/la-user-containment.json
```

After deployment, grant the resulting Managed Identity `Microsoft Sentinel Contributor` on your workspace, and (for containment) the Graph app roles above.
