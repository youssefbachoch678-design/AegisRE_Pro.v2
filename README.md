# AegisRE Pro

AegisRE Pro is an Android workbench for authorized, offline, static inspection of APK files. It does not install or execute the APK under inspection and does not require root access.

## Implemented capabilities

- Open multiple APK files through Android's document picker.
- Inspect ZIP entry names, DEX/native-library/asset counts, and native ABI folders.
- Calculate SHA-256 fingerprints.
- Read DEX headers and bounded DEX tables to display class descriptors, method references, and string samples.
- Inspect plaintext and Android binary XML manifests for package/version, permissions, component declarations, cleartext, debuggable, backup, and Network Security Config reference flags (resource-resolved values may be unavailable).
- Read basic ELF header metadata (class, endianness, machine, and file type).\n- Extract X.509 certificate metadata from legacy META-INF signature entries, including subject, issuer, validity dates, and certificate SHA-256. This is not cryptographic verification of APK v2/v3 signatures.\n- Export a local HTML report through Android's document picker.
- Run an initial static security ruleset for sensitive permission declarations, exported components, cleartext configuration, debuggable/backup flags, HTTP URL strings, and possible embedded-secret patterns.
- Display each finding with severity, confidence label, evidence, explanation, and remediation guidance.
- Enforce APK size, expanded-data, ZIP-entry, and per-DEX parsing limits.

## Important limitations

- Binary AndroidManifest XML is detected but not decoded yet. Manifest parsing currently supports plaintext XML only.
- DEX parsing is a bounded table reader, not a complete DEX/Smali disassembler. Method entries are references and string inspection is capped.
- ELF inspection reads headers only; it does not disassemble native code.
- Resource XML paths are listed, but resource contents and Network Security Config rules are not fully parsed.
- The security ruleset is an initial heuristic scanner. Pattern matches require manual review, and no findings does not prove an APK is safe.
- APK v2/v3 signing-block verification and full signature-integrity verification are not implemented; displayed META-INF certificates are candidates only.\n- PDF report export, APK comparison, and a complete analysis history are not implemented yet. HTML report export is available.

## Safety and privacy

- Analysis is local and static; the selected APK is never launched by AegisRE Pro.
- No root access or network permission is required for the current analysis workflow.
- No APK is uploaded to a server by the analysis workflow.
- Only inspect APKs you own or are authorized to analyze.
- Findings are informational and are not a definitive malware verdict.

## Next roadmap

1. Expand automated tests with synthetic binary-XML, APK/DEX fixtures, malformed-file cases, and large-file cases.
2. Add binary AndroidManifest and resource XML decoding.
3. Add richer DEX navigation and a read-only Smali-style browser.
4. Parse Network Security Config and improve WebView/transport checks.
5. Add certificate/signature inspection and verifiable signature status.
6. Add local HTML report export, APK comparison, and analysis history.

Roadmap items are not claims about features already shipped. Check the release notes and this README for the current implementation status.
