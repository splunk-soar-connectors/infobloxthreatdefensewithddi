# Explanation of Data Ingestion

This integration supports two types of data ingestion: **DNS Security Events** and **IQ for TD Insights**. If an ingestion type is not selected while configuring asset, the integration defaults to ingesting **DNS Security Events**. Only one data ingestion type can be configured per asset. To configure multiple data ingestions, set up multiple assets.

The below details describe the configuration and usage of the Infoblox integration for Splunk SOAR, focusing on the two on-poll ingestion types: **DNS Security Events** and **IQ for TD Insights**.

______________________________________________________________________

## On-Poll Configuration

### Poll Now Feature

The **Poll Now** action retrieves the data based on the **Max Hours Backwards** parameter which is default set to 24 hours for ingestion type **DNS Security Events**.

**Important Notes:**

- The *Poll Now* feature **ignores** the following parameters: **Source ID**, **Maximum containers**, and **Maximum artifacts**.
- The *Poll Now* feature does **not** store a checkpoint file, meaning it will fetch data according to the configured parameters without considering previous ingestions.

### Scheduled / Interval Polling

**Recommended Ingestion:**\
To optimize ingestion and reduce the volume of unnecessary events, it is strongly recommended to apply the maximum number of relevant filters. This ensures efficient processing and minimizes noise in the Splunk SOAR environment.

**Limit Parameter:**\
The `limit` parameter controls the maximum number of records ingested per poll. The default value is **100**; adjust based on your requirements.

**Max Hours Backwards Parameter:**\
For the first poll, this parameter determines how many hours of historical data to fetch. For subsequent polls, the integration uses the timestamp from the last poll as the starting point.

______________________________________________________________________

## DNS Security Events

- **Parameters:**

  - **Max Hours Backwards:** Number of hours before the first connector iteration to retrieve alerts from (integer, default: 24).
  - **Queried name:** Filter by comma-separated queried domain names (string list).
  - **Policy Name:** Filter by comma-separated security policy names (string list).
  - **Threat Level:** Filter by threat severity level (LOW, MEDIUM, HIGH) (string).
  - **Threat Class:** Filter by comma-separated threat category (e.g., "Malware", "MalwareDownload") (string list).
  - **Threat Family:** Filter by comma-separated threat family (e.g., Log4Shell, OPENRESOLVER) (string).
  - **Threat Indicator:** Filter by comma-separated threat indicators (domains, IPs) (string list).
  - **Policy Action:** Filter by comma-separated action performed (Log, Block, Default, Redirect) (string list).
  - **Feed Name:** Filter by comma-separated threat feed or custom list name (string list).
  - **Network:** Filter by comma-separated network name, on-premises host, endpoint, or DFP name (string list).
  - **Limit:** Maximum number of records to retrieve per polling cycle (integer, default: 100).

- **Severity Mapping of DNS Security Events:**

  | Threat Level | SOAR Container Severity |
  |--------------|------------------------|
  | HIGH | High |
  | MEDIUM | Medium |
  | LOW | Low |
  | INFO | Low |

- **Container Creation:**\
  Each DNS Security Event will create a separate container in Splunk SOAR with relevant metadata and artifacts containing the event details.

- **Important API Limitation:**\
  The DNS Security Events API does not support sorting, and records are returned in descending order by default. This may result in data loss if there are more records than the specified limit. To minimize this risk, apply relevant filters and adjust the limit parameter appropriately.

______________________________________________________________________

## IQ for TD Insights

- **Parameters:**

  - **Status:** Filter Insights by their current status. Defaults to `ALL`; when `ALL` is selected, no status filter is sent to the API (string).
  - **Severity:** Filter Insights by severity level (LOW, MEDIUM, HIGH, CRITICAL). Defaults to `ALL`; when `ALL` is selected, no severity filter is sent to the API (string).
  - **Name:** Filter by the user-facing insight name (case-insensitive partial match) (string).
  - **Threat Properties:** Filter by comma-separated threat properties, e.g. `malware,phishing,ransomware` (string).
  - **Date Created:** Filter by the insight creation timestamp. Provide an RFC 3339 date-time value (e.g., `2025-12-19T07:01:56Z`); only insights created on that specific day are returned; this is a single-day filter, not a range from this date to now (string).
  - **Insight ID:** Return a specific insight by its unique display identifier (string).
  - **Indicators:** Filter by comma-separated threat indicators; matches insights whose indicators array contains any of the listed values (string).
  - **Assets:** Filter by comma-separated assets; matches insights whose assets array contains any of the listed values (string).
  - **User:** Filter by comma-separated users; matches insights whose users array contains any of the listed values (string).

- **Severity Mapping of IQ for TD Insights:**

  | Severity Level | SOAR Container Severity |
  |----------------|------------------------|
  | CRITICAL | High |
  | HIGH | High |
  | MEDIUM | Medium |
  | LOW | Low |

- **Container Creation:**\
  Each IQ for TD Insight will create a separate container in Splunk SOAR with relevant metadata and artifacts containing the insight details.

- **Container Updates:**\
  IQ for TD Insight containers and artifacts will not be updated after initial ingestion, even if the insight is updated in Infoblox.

- **Insight Deduplication:**\
  Insights will be deduplicated based on the insight ID to prevent duplicate containers.

______________________________________________________________________

## Best Practices

- **Filtering Recommendations:**\
  To optimize ingestion and reduce the volume of unnecessary events, it is strongly recommended to apply the maximum number of relevant filters. This ensures efficient processing and minimizes noise in the Splunk SOAR environment.

- **Time-based Polling:**\
  DNS Security Events ingestion type uses time-based filtering for incremental polling. The timestamp of the last fetched event will be used as the new polling start time, ensuring only new events are ingested in subsequent polls.

- **Multiple Assets Configuration:**\
  For organizations that need to ingest both DNS Security Events and IQ for TD Insights simultaneously, configure two separate assets, one for each ingestion type.

______________________________________________________________________

## Playbooks

- Playbooks for **Infoblox Threat Defense with DDI** are available in the [repository](https://github.com/infobloxopen/infoblox_splunk_soar/tree/main/Infoblox%20Threat%20Defense%20with%20DDI). Refer to the README for detailed instructions on setup and configuration.

______________________________________________________________________
