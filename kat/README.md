# KAT - Known Answer Tests

Deterministische Testvektoren aus der **echten** TypeScript-Krypto. Der Swift-Core
(`src/apps/apple/Packages/AiondaMailCore`) wird byte-für-byte dagegen verifiziert.
Divergenz = roter Build, nicht Kundenbug. Siehe `src/docs/MACOS_APP_BAUPLAN.md` §4.3.

## Kommandos

```bash
npm run generate-kat   # Fixtures neu erzeugen (kat/fixtures/)
npm run verify-kat     # Fixtures gegen die echten TS-Funktionen zurückprüfen
npx vitest run kat/    # Verifikation + isolierte Regeneration + Bytevergleich
```

Der Generator ist reproduzierbar: zwei Läufe erzeugen byte-identische Dateien.
Der Vitest-Wächter erzeugt alle Fixtures in einem eigenen temporären Verzeichnis
neu und vergleicht die Dateien byteweise. Eine semantisch gültige, aber anders
kodierte Fixture gilt dabei ebenfalls als Drift.

## Grundsatz

Es wird **keine Krypto-Logik nachgebaut**. Der Generator ruft die echten Funktionen
aus `src/crypto/` auf. Wo diese intern Zufall ziehen, wird der Zufall von außen
injiziert (`kat/lib/deterministic.ts`):

- `crypto.getRandomValues` wird durch skriptierte Werte ersetzt (deckt auch
  `@noble/post-quantum` ab, weil `webcrypto === globalThis.crypto`)
- `subtle.generateKey({name:'X25519'})` liefert ein vorgegebenes Schlüsselpaar

Nur dort, wo der Produktivcode eine Schreibrichtung gar nicht besitzt (Legacy-Label
`trashmail-contacts-v2`, Negativ-Fall mit fremdem Label, gzip/Bucket-Padding vor der
Verschlüsselung), wird die Eingabe konstruiert - und anschließend immer mit der
echten Leserichtung gegengeprüft.

## Kodierung

Alle Binärfelder sind **lowercase Hex** ohne Präfix. Felder mit dem Suffix `_utf8`
sind reine Lesehilfen und enthalten dieselben Bytes als Text.

## Dateien

| Datei | Fälle | Inhalt |
|---|---|---|
| `aes_gcm.json` | 12 | AES-256-GCM in drei Speicher-Layouts (`blob_layout`) x vier Klartexten (leer, 1 Byte, Umlaute/Emoji, 2048 Byte) |
| `key_derivation.json` | 6 | `SHA-256(vault_key_string)` und HKDF-SHA-256 mit den Labels `trashmail-folder-key-v1`, `trashmail-tasks-v1`, `trashmail-contacts-v2` sowie leerem Salt |
| `wrapped_key_tasks.json` | 9 | 3 Fälle für das 93-Byte-Wrapping, 5 produktive AAD-Feldkontexte und 1 Legacy-Feld ohne AAD |
| `email_field.json` | 4 | Clientseitig verschlüsseltes Feld (`encrypted_subject` & Co.), inkl. gzip und Bucket-Padding vor der Verschlüsselung |
| `hybrid_kem.json` | 2 | X25519 + ML-KEM-1024 Encapsulation/Decapsulation, vollständig deterministisch |
| `pack_format.json` | 2 | 1661-Byte-Pack `version(1)‖x25519(32)‖mlkem(1568)‖nonce(12)‖wrapped+tag(48)` plus `email_roundtrip` für den End-zu-End-Test |
| `vault_unlock.json` | 25 | Passwort-/Wiederherstellungsableitung, XOR/Shamir, Anteilsformat 1 und 2 samt Herabsetzung und 6 abzulehnenden Chiffretexten (`#4fdb8c92`), je eine vollständige PBKDF2- sowie Argon2id-Entsperrkette |
| `key_transition.json` | 3 + 10 + 6 + 12 | Signierter Postfach-Schlüsselwechsel, Vertrag v2 (`#658912ef`, `docs/VAULT_SCHLUESSELWECHSEL_SIGNATUR.md`): Fingerabdruck v2 (KEM + Signierschlüssel, 3 Fälle), Wechselakten (10: 4 gültig, 6 abzulehnen), Einrichtungsakten mit Challenge-Nonce und Shared Secret (6: 2 gültig, 4 abzulehnen), Seed-AAD, und 12 Kettenläufe (`chain_walks`) mit Soll-Urteil `gleich`/`uebernehmen`/`halt` - darunter der Zweischritt-Tausch aus Abnahme B1 |

Die gzip-Fälle nutzen kanonische, ungepackte DEFLATE-Blöcke. Das ist ein
vollständig gültiger gzip-Strom, dessen Bytes nicht von der zlib-Version und
deren Kompressionsheuristik abhängen. Geprüft wird weiterhin der echte
produktive Entpackpfad.

### `blob_layout` in `aes_gcm.json`

| Wert | Wo im Produktivcode | Lesefunktion |
|---|---|---|
| `iv\|\|ciphertext\|\|tag` | Aufgabenfelder, clientverschlüsselte Mailfelder | `decryptClientAesGcm` / `decryptTaskField` |
| `ciphertext\|\|tag` | `encrypted_content_html` (IV steht separat im Datensatz) | `decryptAesGcm(blob, key, iv)` |
| `nonce\|\|tag\|\|ciphertext` | serverseitig (PHP) verschlüsselte Felder | `decryptPhpAesGcm` |

### `hybrid_kem.json`

`mlkem_seed` ist die 64-Byte-Seed-Darstellung `d‖z` aus FIPS 203 KeyGen - genau die
Form, über die CryptoKit einen ML-KEM-Private-Key importiert. `mlkem_private` (3168
Byte) ist zusätzlich enthalten, muss aber aus dem Seed reproduzierbar sein.
`x25519_ephemeral_private` und `mlkem_message` (m, 32 Byte) erlauben, die
Encapsulation exakt nachzurechnen.

Shared Secret:

```
shared_secret = HKDF-SHA-256(
    ikm  = x25519_shared(32) || mlkem_shared(32),
    salt = leer,
    info = UTF-8("trashmail-hybrid-kem-v1"),
    len  = 32)
```

### `pack_format.json` -> `email_roundtrip`

Vollständige Mail, mit der sich der gesamte Hybrid-KEM-Pfad am Stück prüfen lässt:
Pack parsen -> KEM decapsulieren -> gewrappten Ephemeral-Key öffnen (PHP-Layout
`tag(16)‖ciphertext(32)`) -> Felder im PHP-Layout entschlüsseln.

## Sync ins Swift-Repo

Die Fixtures leben hier (Single Source of Truth) und werden kopiert nach:

```
src/apps/apple/Packages/AiondaMailCore/Tests/AiondaMailCoreTests/Fixtures/kat/
```

## Aufbau

```
kat/
├── generate-kat.ts        # erzeugt die Fixtures
├── verify-kat.ts          # prüft sie gegen die echten TS-Funktionen zurück
├── kat.spec.ts            # dasselbe als vitest-Spec (CI-Wächter)
├── lib/
│   ├── deterministic.ts   # Zufallsinjektion, X25519-Helfer
│   ├── fixture-drift.ts   # byteweiser Vergleich inkl. fehlender/zusätzlicher Dateien
│   ├── helpers.ts         # Padding/gzip/HKDF-Bausteine für Testmaterial
│   └── types.ts           # Fixture-Schema
└── fixtures/*.json
```
