# third_party

## zip2hashcat

- **Upstream:** https://github.com/oliverjueguen/zip2hashcat
- **Version:** 1.1.0
- **License:** MIT — see [`zip2hashcat.LICENSE`](./zip2hashcat.LICENSE)
- **Why it is vendored:** Debian's `john` package is the *core* build and does
  not ship `zip2john`, so there was no way to turn a ZIP into a hashcat hash.
  `zip2hashcat` is a zero-dependency, standalone Python script that extracts
  ZipCrypto **and AES** ZIP hashes in native hashcat format, so `hashcat`
  (`-m 17200/17210/17220/17225/13600`) can crack them.

Nothing here is modified; re-download from upstream to update.
