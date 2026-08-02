**Unreleased**

* Retry the last successful DNS event second so later same-second failures remain eligible for ingestion.
* Reject dot-only insight and job identifiers before authenticated API path construction.
