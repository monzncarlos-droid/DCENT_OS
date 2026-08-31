# Byte-exact AMTC config fixtures

These nine Base64 files encode the exact raw held AMTC `Config.ini` artifacts
admitted by `factory_test_plan.rs`. Base64 is used so Git/apply-patch newline
normalization cannot alter source bytes (the S19 Pro artifact contains CRLF;
the other eight contain LF).

The unit tests decode in memory, verify the published SHA-256, and pass the raw
bytes to the pure importer. The fixtures are evidence only: no jig binary is
included or executed, and nothing here grants device, repair, manufacturing,
grading, pattern-dispatch, voltage, frequency, fan, PIC, or EEPROM authority.

Hashes and semantic provenance for the original eight profiles are recorded in
.
The T9+ fixture is the exact 2,172-byte content of
+`, SHA-256
`2c336abff413e5918cd09e28c2d89d4f228cf4a10350630cd8c4bc350d78ba66`.
