# DNS Log Analysis Using Splunk SIEM

## Introduction

DNS (Domain Name System) logs contain information about DNS requests made by systems on a network. Analyzing DNS logs can help understand network activity and identify unusual DNS behavior.

In this beginner-level project, I used **Splunk Enterprise** to analyze a sample DNS log file.

The project focuses on basic Splunk log analysis using beginner-level **Search Processing Language (SPL)** queries.

---

## 🛠️ Tools Used

- **Splunk Enterprise**
- **Windows**
- **DNS Log File**
- **SPL (Search Processing Language)**

---

## 📋 Prerequisites

Before starting the project, the following were required:

- Splunk Enterprise installed and running
- Sample DNS log file
- Basic knowledge of DNS
- Basic understanding of Splunk

---

# Phase 1: Upload DNS Logs to Splunk

The DNS log file was uploaded to Splunk using the **Add Data** option.

The log file was configured with the appropriate source and sourcetype.

After uploading the data, the events were verified using the Splunk **Search & Reporting** application.

### Check DNS Events

```
source="dns_record.log" sourcetype="dns_record"
```
This search displays the DNS events collected from the log file. 

---

# Phase 2: Count DNS Events

After verifying that the logs were successfully indexed, the total number of DNS events was counted.

```
source="dns_record.log" sourcetype="dns_record"
| stats count
```

The stats count command counts the total number of events returned by the search.

This provides a basic overview of the amount of DNS data available for analysis.

---

# Phase 3: View DNS Events

The first few events were viewed to understand the structure and information contained in the DNS logs.

```
source="dns_record.log" sourcetype="dns_record"
| head 10
```
The head command displays the first 10 events returned by the search.

This helped in understanding the raw DNS log format before performing further analysis.

---

# Phase 4: Extract DNS Query Information

The DNS query information was extracted from the raw log data.
```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval query=mvindex(fields, 8)
| table query
```

### Explanation

- `split()` separates the raw log using tab characters.
- `mvindex()` selects the required field.
- `table query` displays the extracted DNS query.

This made it easier to analyze the domains requested in the DNS logs.

---

# Phase 5: Analyze Frequently Queried Domains

After extracting the DNS query, the number of requests for each domain was counted.

```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval query=mvindex(fields, 8)
| stats count by query
| sort - count
```
Explanation

The query:

- Extracts the DNS query.
- Counts how many times each query appears.
- Sorts the results from highest to lowest count.

This provides a basic view of the most frequently requested domains.

---

# Phase 6: Analyze Source IP Addresses

The source IP addresses in the DNS logs were analyzed to understand which systems generated DNS requests.
```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval src_ip=mvindex(fields, 1)
| stats count by src_ip
| sort - count
```
This counts DNS events associated with each source IP address.

The results can help identify which systems generated the highest number of DNS requests.

---

# Phase 7: Analyze DNS Record Types

DNS requests can contain different record types such as A, AAAA, CNAME, MX, and others.

The record types were extracted and counted using:
```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval qtype=mvindex(fields, 9)
| stats count by qtype
| sort - count
```

This provides a basic overview of the DNS record types present in the dataset.

---
# Phase 8: Analyze DNS Response Codes

DNS response codes provide information about the result of DNS requests.

The response code was extracted and analyzed using:
```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval rcode=mvindex(fields, 10)
| stats count by rcode
| sort - count
```

This shows the number of DNS events associated with each response code.

---

# Phase 9: Check for NXDOMAIN Requests

`NXDOMAIN` is a DNS response indicating that the requested domain does not exist.

A basic search was performed to check for NXDOMAIN activity:
```
source="dns_record.log" sourcetype="dns_record"
| search "NXDOMAIN"
| stats count
```
This provides the total number of events containing `NXDOMAIN`.

View NXDOMAIN Events
```
source="dns_record.log" sourcetype="dns_record"
| search "NXDOMAIN"
```
If NXDOMAIN events are present, they can be investigated further to understand the requested domains and source systems.

---

# Phase 10: Analyze High-Volume DNS Clients

The source IP analysis was used to identify systems generating a large number of DNS requests.
```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval src_ip=mvindex(fields, 1)
| stats count by src_ip
| sort - count
```
The results are sorted so that IP addresses generating more DNS events appear first.

This is a simple method of identifying high-volume DNS clients.

---

# Phase 11: Analyze Long DNS Queries

Long DNS queries can be examined as part of basic DNS log analysis.

The query field was extracted and its length was calculated:
```
source="dns_record.log" sourcetype="dns_record"
| eval fields=split(_raw, "\t")
| eval query=mvindex(fields, 8)
| eval query_length=len(query)
| where query_length > 30
| table query query_length
| sort - query_length
```

This displays DNS queries longer than 30 characters.

Long queries are not automatically malicious, but they can be investigated further when performing security analysis.

---
# 📊 Analysis Performed

The following activities were performed during this project:

- Uploaded DNS logs into Splunk
- Verified DNS events
- Counted total DNS events
- Viewed raw DNS events
- Extracted DNS query information
- Identified frequently queried domains
- Analyzed source IP addresses
- Analyzed DNS record types
- Analyzed DNS response codes
- Checked for NXDOMAIN requests
- Identified high-volume DNS clients
- Checked for long DNS queries

---

# 🔎 SPL Commands Used

The project introduced several basic SPL commands:

| SPL Command | Purpose |
|---|---|
| `search` | Search for specific events |
| `stats` | Calculate event counts |
| `sort` | Sort search results |
| `head` | Display the first events |
| `eval` | Create or calculate fields |
| `split` | Split raw data into fields |
| `mvindex` | Select a specific field |
| `table` | Display selected fields |
| `where` | Filter results based on a condition |
| `len` | Calculate string length |

---

# 🧠 What I Learned

Through this project, I gained practical experience with:

- DNS log analysis
- Splunk Enterprise
- SIEM-based log analysis
- Basic SPL
- Searching security events
- Counting and sorting events
- Extracting fields from raw logs
- Analyzing DNS queries
- Analyzing source IP addresses
- Understanding DNS response codes
- Performing basic security analysis

---

# Conclusion

This project provided hands-on experience with **Splunk SIEM and DNS log analysis**.

Using basic SPL queries, DNS events were searched, counted, filtered, and analyzed to understand DNS activity.

The project helped build a foundation in **SIEM, log analysis, SOC monitoring, and cybersecurity operations**.

---

## 👨‍💻 Author

**Bhavya Bhaskar Arora**

Cybersecurity | SOC | SIEM 
