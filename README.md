# AegisRE Pro

AegisRE Pro is an Android workbench for authorized, offline, static inspection of APK files. It does not install or execute the APK under inspection and does not require root access.

## Current capabilities

- Open multiple APK files through Android's document picker.
- Inspect ZIP entry names, DEX/native-library/asset counts, and native ABI folders.
- Calculate SHA-256 fingerprints.
- Read DEX headers and bounded DEX tables to display class descriptors, method references, and string samples.
- Enforce APK size, expanded-data, ZIP-entry, and per-DEX parsing limits.

## Safety and privacy

- Analysis is local and static; the selected APK is never launched by AegisRE Pro.
- No root access or network permission is required for the current analysis workflow.
- Only inspect APKs you own or are authorized to analyze.
- Results are informational and do not constitute a definitive malware verdict.

## Roadmap

- Complete Smali disassembly and class/method navigation.
- Manifest and permission inspection.
- Resource/XML browser.
- Native ELF metadata viewer.
- Searchable findings and TXT/HTML report export.

Roadmap items are not claims about features already shipped. Check the release notes and this README for the current implementation status.
