# AegisRE Pro

AegisRE Pro is an Android workbench for authorized, offline, static inspection of APK files. It does not install or execute the APK under inspection and does not require root access.

## Implemented capabilities

- Open multiple APK files through Android's document picker.
- Inspect ZIP entry names, DEX/native-library/asset counts, and native ABI folders.
- Calculate SHA-256 fingerprints.
- Read DEX headers and bounded DEX tables to display class descriptors, method references, and string samples. DEX strings are decoded as Modified UTF-8; this is not a complete DEX/Smali disassembler.
- Inspect plaintext and a limited subset of Android binary XML manifests for package/version, permissions, component declarations, cleartext, debuggable, backup, and Network Security Config reference flags. Binary XML resource references and some typed values are not resolved.
- Read basic ELF header metadata (class, endianness, machine, and file type); native code is not disassembled.
- Extract X.509 certificate metadata from legacy META-INF signature entries, including subject, issuer, validity dates, and certificate SHA-256. This is not cryptographic verification of APK v1/v2/v3 signatures.
- Export a local HTML report through Android's document picker.
- Run an initial heuristic static ruleset for selected permissions, exported components, cleartext configuration, debuggable/backup flags, HTTP URL strings, WebView API indicators, legacy storage indicators, and possible embedded-secret patterns.
- Display findings with severity, confidence label, evidence, explanation, and remediation guidance.
- Enforce APK size, expanded-data, ZIP-entry, and per-DEX parsing limits.

- Open-source companion-tool directory links to JADX, Apktool, Androguard, OWASP MASTG, and MobSF. These are external references and are not embedded engines in this Android app.

## Known limitations

- Binary AndroidManifest XML support is partial; resource IDs, namespaces, and all typed values are not comprehensively resolved. Parse failures may result in incomplete metadata.
- DEX parsing is limited to selected ID tables and string data. It does not decode code items, control flow, annotations, debug info, or produce Smali.
- ELF inspection reads headers only; it does not disassemble native code or inspect imports/exports.
- Resource XML paths are listed, but resource contents and Network Security Config rules are not parsed.
- The security ruleset is heuristic. Pattern matches require manual review, and no findings does not prove an APK is safe.
- META-INF certificate extraction is certificate metadata only. APK Signing Block v2/v3 verification and complete v1 signature-integrity verification are not implemented.
- HTML report export is available. PDF export, APK comparison, and persistent analysis history are not implemented.

## Safety and privacy

- Analysis is local and static; the selected APK is never launched by AegisRE Pro.
- No root access or network permission is required for the current analysis workflow.
- No APK is uploaded to a server by the analysis workflow.
- Only inspect APKs you own or are authorized to analyze.
- Findings are informational and are not a definitive malware verdict.

## Validation status

The GitHub Actions workflow runs `testDebugUnitTest` and `assembleDebug`. A successful build confirms compilation and unit-test task completion, not correctness across all APK formats or runtime behavior. Test coverage is still limited and should be expanded with real-world, legally obtained APK fixtures and malformed-file cases.
