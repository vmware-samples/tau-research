# VMware Threat Report 2022: Dataset Metadata

This distribution package contains some key metadata of dataset samples used in the 2022 VMware Threat Report "Exposing Malware in Linux-based Multi-Cloud Environments".
All samples are publicly available on VirusTotal. 
Note that for some of the samples a dynamically created memory dump is also included.

The package has following files:

```
├── README.md
├── bin.zip (compressed as multiple files: bin.zip, bin.z01-bin.z05)
├── bin_memory.zip
├── dist_dataset.json
├── strings.zip
└── strings_memory.zip
```

## File: dist_dataset.json
This file contains basic sample metadata, e.g.:
```
{
    "class": "ransomware",
    "entropy": 6.037467897008342,
    "family": "blackmatter",
    "filename": "1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f.bin",
    "ignore": false,
    "is_memory_dump": false,
    "is_stripped": false,
    "md5": "3f328e68ed4d59973f9c5b4f36545ab0",
    "obfuscation": null,
    "parent": [],
    "sha1": "f2724c0abb93b6a1d3f6fcb59b88c2aebbd76031",
    "sha256": "1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f",
    "telfhash": "t1bc21ee0da93d0abd4aa55d20e95967e38247c23662766706ffa5cec4866f80af10cc0f"
}
```
where:
* _class_ - is the class the sample belongs to
* _entropy_ - is the entropy of the sample
* _family_ - is the family the sample belongs to
* _ignore_ - specifies whether the sample is ignored (true) or included (false)
* _is_memory_dump_ - specifies whether the sample is a memory dump or not
* _is_stripped_ - specifies whether the sample is stripped or not
* _obfuscation_ - specifies whether the sample is obfuscated (e.g., UPX packed) or not
* _telfhash_ - is the telfhash value of the sample

There are 280 samples in total, including
* **Cryptominers**: 183
    * Originally not packed: 39
    * Originally packed: 50
    * Un-packed from the originally packed ones: 50
    * Memory dumps: 44
* **Ransomware**: 66
    * Originally not packed: 66
* **RAT**: 31
    * Originally not packed: 31

## File: strings.zip
This ZIP archive file contains strings of non-memory dump samples. More specifically:
* Cryptominer samples - strings were generated with the _strings_ tool in Linux.
* Ransomware samples - strings were collected from the [VMware NSX sandbox](https://www.vmware.com/products/nsx-sandbox.html) dynamic analysis.
* RAT samples - strings were collected from the [VMware NSX sandbox](https://www.vmware.com/products/nsx-sandbox.html) dynamic analysis.

## File: strings_memory.zip
This ZIP archive file contains strings of memory dump samples, generated with the _strings_ tool in Linux.

## Files: bin.zip (**password-protected**)
The password-protected ZIP archive files (bin.zip, bin.z01-z05) contain all samples that are not from memory dump, with two filename formats:
* sha256.bin - it means the sample is the original sample we collected (without any parent).
* sha256_unpacked_sha256.bin - it means the sample (specified by 2nd sha256) is unpacked from a parent sample (specified by the 1st sha256). For example, ```dd31b774397c6e22375d4f2fe26e38e82ae164bc73cf58314b18b8eed26802f0_unpacked_d5ce80121f274fea8066b4f3e99f93fc0767783aa6c658252b7bbaea7648d196.bin``` is an unpacked sample (_d5ce80121f274fea8066b4f3e99f93fc0767783aa6c658252b7bbaea7648d196_) which is unpacked from _dd31b774397c6e22375d4f2fe26e38e82ae164bc73cf58314b18b8eed26802f0_.

Steps to decompress the ZIP archive files:
1. Run the command to combine the multiple ZIP files: ```zip -F bin.zip --out single_bin.zip```
2. Run the command to decompress the single ZIP file (password needed): ``` unzip single_bin.zip```
This should create a folder ```bin``` with binary files inside.

## File: bin_memory.zip (**password-protected**)
The password-protected ZIP archive file contains all memory dump files from the cryptominer samples.
To decompress the ZIP archive file (password needed), run: ``` unzip bin_memory.zip```

## Contact
Should you have any questions on the data, please contact the VMware NSX Threat Intelligence Team: [threat-intelligence-team@groups.vmware.com](threat-intelligence-team@groups.vmware.com)
