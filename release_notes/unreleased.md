**Unreleased**

* Validated caller-supplied list identifiers before using them in write-action URL paths. [PAPP-38209, PSAAS-30924]
* Restricted indicator intelligence lookups to the documented indicator-type endpoints. [PAPP-38209, PSAAS-31153]
* Encoded insight and job identifiers as single URL path segments. [PAPP-38209, PSAAS-31254]
* Preserve critical and unknown upstream severities as high-severity SOAR data. [PAPP-38209, PSAAS-32194]
* Preserve the DNS event checkpoint at the first failed save and warn when a poll reaches its result cap. [PAPP-38209, PSAAS-32346]
* Normalize Add and Remove input before selecting the custom-list item mutation. [PAPP-38209, PSAAS-32419]
