## Context
_Defending and Attacking Azure Workloads_ was a workshop I attended in Huntsville, Alabama, at the 2025 National Cyber Summit. I worked alongside SANS instructors to gain hands-on experience with Microsoft Azure Sentinel and deepen my understanding of tools such as the MITRE ATT&CK framework. I decided to document what I learned from this experience to show my cybersecurity growth and to discuss my takeaways.

## Lab Overview
When an organization operates, it often must comply with specific industry standards and frameworks. Documents such as those provided by NIST outline key security considerations, including incident response procedures. The phases of incident response are: Preparation > Detection > Analysis > Containment > Eradication > Recovery.

The first two phases, Preparation and Detection, represent the organization’s initial line of defense against attackers. These stages involve understanding potential attack methods and developing security controls to detect malicious activity as it occurs.

The purpose of this lab is to simulate how a cybersecurity engineer might design and implement such controls to protect a cloud environment.

## 1: Infrastructure Deployment
The initial step of this workshop involves deploying Infrastructure as Code (IaC) from a <a href="https://github.com/bluemountaincyber/building-detections-azure">GitHub repository</a>. The purpose of this is to replicate a production environment that deploys IaC to automatically provision cloud resources. For this deployment, a resource group is created that contains a honeypot file named **`secretdata-final-instructions.txt`**.

## 2: True-Positive Event Creation
We can perform true-positive event creation utilizing <a href="https://attack.mitre.org/techniques/T1619/">ATT&CK T1619 Cloud Storage Object Discovery</a>. This process involves enumeration of cloud resources using the Azure CLI.

This can be done with a command written as, **`az storage container list --account-name $storageAccount --auth-mode login | jq .`**. The command is composed of **az storage container list** (list blob storage containers), **--account-name $storageAccount** (target storage account), **--auth mode login** (use Azure credentials), and **| jq .** (format output as JSON data). From there, an adversary may notice the secretdata honeyfile as mentioned previously. 

This can then be exfiltrated using the common PowerShell command **Get-Content**.

## 3: Configuring Logging
The MITRE ATT&CK framework outlines how adversaries can obtain and abuse cloud credentials to access sensitive data stored in online databases and cloud storage accounts. This technique, defined under <a href="https://attack.mitre.org/techniques/T1078/004/">MITRE ATT&CK T1078.004</a>, offers valuable insight into effective and recommended mitigations. 

For the purposes of this lab, we are primarily concerned with implementing detective security controls to identify when anomalous storage access occurs.

<img src="https://i.imgur.com/RxALhaa.png">

Microsoft Azure provides monitoring functionality for resources but must be configured first. <br>

<p align="center">
<img src=https://i.imgur.com/ToqTU25.png height="250" width="250">
<img src=https://i.imgur.com/aEio5Ed.png height="300" width="300">
<img src=https://i.imgur.com/3SUuzT4.png height="300" width="300">
<img src=https://i.imgur.com/Kllefa8.png height="300" width="300">
<img src=https://i.imgur.com/FcJsP93.png height="600" width="700">
</p>

This allows the Azure environment to generate logs for the selected resources. If we repeat step 2, true-positive event creation, we will now get a log showing that the resources were accessed.

## 4: Creating the Detection Rule & Automation
Now that logging is configured, we can repeat the process of true-positive event creation and capture logs of events as they occur. However, parsing through a large volume of logs manually is not practical. Relevant events can be filtered and forwarded to the Microsoft Azure Sentinel SIEM using Kusto Query Language (KQL).

<p align="center">
<img src=https://i.imgur.com/ZmL17sy.png height="500" width="700">
</p> 

`StorageBlobLogs` targets StorageBlobLogs as the table being queried. <br>
`where AccountName startswith "prodddata"` filters the logs for the storage account containing the honeypot. <br>
`where OperationName == "GetBlob"` filters the logs by GetBlob (blob exfiltration) actions. <br>
`where ObjectKey endswith "final-instructions.txt"` filters the logs by specific honeypot file access. <br>
`extend AttackerIP = split(CallerIpAddress, ':')[0]` grabs the IP address associated with the attacker. <br>
`sort by TimeGenerated desc` timestamps the event. <br>

Next, we create a schedule for this rule to be checked and forward it as an incident if it returns true.

<p align="center">
<img src=https://i.imgur.com/KnwyJib.png height="400" width="400">
<img src=https://i.imgur.com/QAFQ6kR.png height="500" width="500">
<img src=https://i.imgur.com/L3P6a2p.png height="500" width="700">
</p>

This should be automated for continuous checks.

<p align="center">
<img src=https://i.imgur.com/RR6aKwX.png height="300" width="300">
<img src=https://i.imgur.com/iItdCQC.png height="500" width="300">
<img src=https://i.imgur.com/dNqq7Cp.png height="500" width="700">
</p>

Now that the rule is developed and automated, we need to verify it is functional.

## 5: Testing the Detection Rule & Automation
Repeat the process of step 2 and review the Sentinel incidents.

<p align="center">
<img src=https://i.imgur.com/tWCvt0C.png height="500" width="500">
<img src=https://i.imgur.com/WJ5raji.png height="500" width="300">
<img src=https://i.imgur.com/FnKtBae.png height="500" width="700">
</p>

This validates the detection and automation rules are working. Now, when an attacker attempts to access the honeypot it will be forwarded as an incident, allowing incident response teams to respond to the threat as it occurs.

## 6: Tearing Down Resources
Run `cd ~/building-detections-azure/terraform` and `terraform destroy`.

## Conclusion
Coming into this workshop, I had little to no understanding of cloud environments or the tools used to manage and secure them. Concepts like cloud storage, logging, monitoring, and incident response were covered in my studies, but I wasn’t sure how they actually work in practice. Participating in this workshop gave me an opportunity to get hands-on experience and understand how they might be deployed in a real environment.
