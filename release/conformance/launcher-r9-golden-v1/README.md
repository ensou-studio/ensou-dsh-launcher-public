# Launcher r9 golden conformance fixture

`fixture.v1.json` is a byte-pinned, self-contained capture from the real
Enterprise Stable happy r8-to-r9 path in
`release/scripts/Test-LauncherStablePromotionOrchestration.ps1`.

The fixture stores the five state-package JSON documents, the companion
promotion bundle, its five payloads, and the public response-trust document as
base64. It stores no private key. The metadata records the generator, producer,
orchestrator, and schema hashes observed when the capture was made.

Two independent pins protect the fixture:

- raw fixture SHA-256:
  `9c9d9aad4e3be5b7631cd6e9008a9e4b35b6965f08e9a6e9b30ae5533d7c0922`
- logical fixture-set SHA-256:
  `c45aab11ac642cb0932f534cff2f9de32f5f6989f78d6a90e12c61c70d4874fa`

Run `pwsh -NoProfile -File release/conformance/Test-LauncherR9GoldenFixture.ps1`.
The test verifies every decoded byte and schema pin, materializes only beneath a
fresh temporary directory, and invokes the production bundle-admission API.

Regeneration is a reviewed operation: run the recorded generator happy path,
capture the exact r9 state package and companion bundle, discard the ephemeral
P-256 private key, update the metadata and both pins, and copy the identical
fixture to the Control repository. Never edit decoded fixture members by hand.
