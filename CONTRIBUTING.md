# Contributing to AegisRE Pro

Thank you for your interest in improving AegisRE Pro!

## How to contribute

1. Open an Issue to describe a bug or suggest an improvement.
2. For code changes, fork this repository.
3. Create a focused branch in your fork and make your changes.
4. Test your changes and explain what you tested.
5. Open a Pull Request against the `main` branch and describe the change.

The project maintainer reviews every Pull Request. Changes are not part of the official project unless the maintainer approves and merges them.

## Project safety boundaries

Contributions must keep AegisRE Pro focused on authorized, defensive, static APK analysis.

- Do not add code that executes APK contents or unknown binaries.
- Do not add exploit, malware deployment, credential theft, stealth, persistence, or security-control bypass features.
- Do not upload APKs or other potentially sensitive samples without clear authorization.
- Keep analysis local where practical, and document any data handling.
- Add reasonable file-size, archive-entry, and resource limits when processing untrusted files.

## Pull Request checklist

- [ ] The change has a clear purpose.
- [ ] I tested the change and described the results.
- [ ] I did not include secrets, tokens, private data, or unauthorized samples.
- [ ] The change follows the project's safety boundaries.
- [ ] Documentation is updated when needed.

By submitting a contribution, you agree that it may be reviewed, requested for changes, or declined by the maintainer.
