# Emotet C2 Configuration Extraction and Analysis: Dataset IoCs

This distribution package contains some key IoCs of dataset samples used in the Report "Emotet C2 Configuration Extraction and Analysis". Note that we may update this package when more IoCs become available.

The package has following files:

```
├── README.md
├── ioc_c2_config.csv
└── ioc_dlls.csv
```

## File: ioc_c2_config.csv
This file contains IoCs of the C2 configurations and other metadata, e.g.:
```
"IP address": "61.7.231[.]229"
"Port": 443
"Epoch": 5
"JARM fingerprint": "2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6a"
"AS number": 9931
"First seen": "2022-02-22 20:44:05 UTC"
```
where:
* _JARM fingerprint_ - queried from VirusTotal (VT). It is believed that VT used the standard port 443 when fingerprinting the server, so we only included the JARM fingerprint hashes for those C2 IP addresses with port 443.
* _First seen_ - the first seen timestamp in our telemetry data.

## File: ioc_dlls.csv
This file contains the DLL payloads which contain the C2 configurations, e.g.:
```
"DLL payload": "4bc1121eb3b1d5f865d219100c849580db3ad649829e2051a63d3f8bd72dc821"
"Epoch": 4
"First seen": "2022-03-01 13:14:58 UTC"
```
where:
* _First seen_ - the first seen timestamp in our telemetry data.

## Contact
Should you have any questions on the data, please contact [the VMware NSX TAU](mailto:threat-intelligence-team@groups.vmware.com?subject=[GitHub]Emotet%20C2%20Configuration%20Extraction%20and%20Analysis:%20Dataset%20IoCs)
