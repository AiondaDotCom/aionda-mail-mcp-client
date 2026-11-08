/**
 * Schema der KAT-Fixtures (Known Answer Tests).
 *
 * Feste Vereinbarung mit dem Swift-Core (AiondaMailCore): alle Binärdaten sind
 * lowercase Hex ohne Präfix. Felder mit dem Suffix `_utf8` sind reine
 * Lesehilfen und enthalten dieselben Bytes als Text.
 *
 * @author Stephan Ferraro
 * @company Aionda GmbH
 */

/** Herkunftsangabe, steckt in jeder Fixture-Datei. */
export interface GeneratorInfo {
    source: string;
    date: string;
}

export interface FixtureFile<T> {
    generator: GeneratorInfo;
    /** Kurzbeschreibung des Formats, damit die Datei für sich lesbar bleibt. */
    encoding: string;
    cases: T[];
    note?: string;
}

/** 1. aes_gcm.json */
export interface AesGcmCase {
    name: string;
    layout: 'webcrypto' | 'php';
    /** Wie stored_blob tatsächlich persistiert wird. */
    blob_layout: 'iv||ciphertext||tag' | 'ciphertext||tag' | 'nonce||tag||ciphertext';
    key: string;
    iv: string;
    plaintext: string;
    plaintext_utf8: string;
    stored_blob: string;
}

/** 2. key_derivation.json */
export interface KeyDerivationCase {
    name: string;
    kind: 'sha256_master' | 'hkdf';
    input: string;
    input_utf8?: string;
    salt: string;
    salt_utf8?: string;
    info: string;
    info_utf8?: string;
    expected: string;
}

/** 3. wrapped_key_tasks.json */
export interface WrappedTaskKeyCase {
    name: string;
    master_key: string;
    salt: string;
    iv: string;
    payload_key: string;
    label: string;
    /** Vollständige AES-GCM-AAD als UTF-8; fehlt bei Legacy-Vektoren. */
    additional_data_utf8?: string;
    wrapped_blob: string;
    expect?: 'auth_failure';
}

export interface TaskFieldCase {
    name: string;
    task_key: string;
    iv: string;
    plaintext_utf8: string;
    /** Feldkontext ohne Versionspräfix, z. B. title oder list-name. */
    field_context: string;
    /** Vollständige AES-GCM-AAD als UTF-8; fehlt bei Legacy-Vektoren. */
    additional_data_utf8?: string;
    stored_blob: string;
}

export interface WrappedTaskKeyFile extends FixtureFile<WrappedTaskKeyCase> {
    field_cases: TaskFieldCase[];
}

/** 4. email_field.json */
export interface EmailFieldCase {
    name: string;
    vault_key_string: string;
    master_key: string;
    iv: string;
    plaintext: string;
    plaintext_utf8: string;
    stored_blob: string;
    compressed: boolean;
    /** Bucket-Padding (0xDEAD) vor der Verschlüsselung angewendet. */
    padded: boolean;
}

/** 5. hybrid_kem.json */
export interface HybridKemCase {
    name: string;
    x25519_private: string;
    x25519_public: string;
    mlkem_seed: string;
    mlkem_public: string;
    mlkem_private: string;
    /** Ephemerer X25519-Private-Key des Absenders (Reproduzierbarkeit). */
    x25519_ephemeral_private: string;
    /** ML-KEM-Nachricht m (32 Byte), macht encapsulate deterministisch. */
    mlkem_message: string;
    kem_x25519_ct: string;
    kem_mlkem_ct: string;
    shared_secret: string;
}

/** 6. pack_format.json */
export interface PackFormatCase {
    name: string;
    blob: string;
    parsed: {
        version: number;
        x25519_ct: string;
        mlkem_ct: string;
        nonce: string;
        wrapped_key: string;
    };
}

/**
 * Zusatzmaterial in pack_format.json: eine vollständig verschlüsselte Mail,
 * damit der gesamte Hybrid-KEM-Pfad (Pack parsen, Key auspacken, Felder
 * entschlüsseln) am Stück geprüft werden kann.
 */
export interface EmailRoundtripMaterial {
    x25519_private: string;
    mlkem_private: string;
    ephemeral_key: string;
    wrapped_ephemeral_key: string;
    encrypted_subject: string;
    encrypted_from: string;
    encrypted_to: string;
    subject_utf8: string;
    from_utf8: string;
    to_utf8: string;
}

export interface PackFormatFile extends FixtureFile<PackFormatCase> {
    email_roundtrip: EmailRoundtripMaterial;
}

/** 7. vault_unlock.json */
export interface PasswordKeyCase {
    name: string;
    password_utf8: string;
    /** UTF-8-Bytes des Passworts, damit Kodierungsfehler auffallen. */
    password: string;
    salt: string;
    /**
     * Kennung aus `vault_shares.derivation`. // #478cc256
     *
     * 🚩 Sie steht im Vektor, weil eine Testreihe, die nur EIN Verfahren
     * kennt, nach der Umstellung gruen bleibt, waehrend der Code etwas
     * anderes rechnet. Genau davor warnt das Ticket.
     */
    derivation: 'pbkdf2_sha256_600k' | 'argon2id_m65536_t3_p4';
    /** PBKDF2: Runden. Argon2id: Durchgaenge (t). */
    iterations: number;
    /** Nur Argon2id: Speicher in KiB (m). Bei PBKDF2 null. */
    memory_kib: number | null;
    /** Nur Argon2id: Spuren (p). Bei PBKDF2 null. */
    parallelism: number | null;
    expected: string;
}

export interface RecoveryHashCase {
    name: string;
    /** Rohe Nutzereingabe, absichtlich unsauber (Nummerierung, Zeilenumbrueche, Grossschreibung). */
    raw_input: string;
    normalized: string;
    expected: string;
}

export interface ShareXorCase {
    name: string;
    share: string;
    derived_key: string;
    encrypted: string;
}

/**
 * Ein Anteil im versionierten Anteilsformat (#4fdb8c92).
 *
 *   1  encrypted = share XOR derived_key                        (32 Byte, kein Kopf)
 *   2  encrypted = 0x02 || share XOR wrapping_key               (33 Byte)
 *      wrapping_key = HKDF-SHA-256(derived_key, salt=leer, info="aionda-vault-share-v2", 32)
 *
 * `downgraded_to_v1` ist derselbe Chiffretext OHNE Kopfbyte - genau das, was
 * ein Angreifer schreiben wuerde, um Format 2 auf Format 1 herabzusetzen.
 * `downgraded_share` ist, was ein Leser daraus macht: 32 Byte Muell, die mit
 * `share` nichts zu tun haben. Beide Felder gibt es nur fuer Version 2.
 */
export interface ShareFormatCase {
    name: string;
    version: 1 | 2;
    share: string;
    derived_key: string;
    wrapping_key: string;
    encrypted: string;
    downgraded_to_v1?: string;
    downgraded_share?: string;
}

/**
 * Chiffretexte, die KEIN Leser oeffnen darf - sie tragen eine unbekannte
 * Version oder eine Laenge, die nicht zu ihrer Version passt. Ein Leser, der
 * hier irgendetwas zurueckgibt statt zu werfen, raet.
 */
export interface ShareFormatRejectedCase {
    name: string;
    encrypted: string;
    reason: 'unknown_version' | 'length_mismatch' | 'empty';
}

export interface ShamirCase {
    name: string;
    secret: string;
    shares: { x: number; data: string }[];
    /** Welche x-Werte fuer die Rekonstruktion genommen werden. */
    reconstruct_from: number[];
}

/**
 * Die vollstaendige Entsperr-Kette eines echten Postfachs: aus Passwort und
 * Wiederherstellungswoertern zurueck zum Master Key und weiter zum privaten
 * Schluesselbund. Genau das muss ein nativer Client koennen.
 */
export interface UnlockChainMaterial {
    master_key: string;
    password_utf8: string;
    recovery_mnemonic: string;
    /** So wie der Server sie in `vault_shares` ablegt. */
    shares: {
        index: number;
        type: 'password' | 'passkey' | 'recovery';
        encrypted: string;
        salt?: string;
        /** Nur beim Passwort-Anteil: welche Ableitung ihn verpackt hat. */
        derivation?: 'pbkdf2_sha256_600k' | 'argon2id_m65536_t3_p4';
    }[];
    /** Master-Key-verschluesselter Schluesselbund - der Beweis, dass der Key stimmt. */
    encrypted_private_key: string;
    private_key_iv: string;
    x25519_private: string;
    mlkem_private: string;
}

export interface VaultUnlockFile {
    generator: GeneratorInfo;
    encoding: string;
    password_keys: PasswordKeyCase[];
    recovery_hashes: RecoveryHashCase[];
    share_xor: ShareXorCase[];
    /** Versioniertes Anteilsformat, beide Versionen. // #4fdb8c92 */
    share_format: ShareFormatCase[];
    /** Chiffretexte, die jeder Leser ablehnen MUSS. // #4fdb8c92 */
    share_format_rejected: ShareFormatRejectedCase[];
    shamir: ShamirCase[];
    /** Bestandspostfach: der Passwort-Anteil haengt an PBKDF2. */
    unlock_chain: UnlockChainMaterial;
    /**
     * Postfach nach der Umstellung: derselbe Ablauf, aber der Passwort-Anteil
     * haengt an Argon2id. // #478cc256
     *
     * 🚩 BEIDE Ketten stehen hier, weil eine Umstellung in BEIDE Richtungen
     * gemessen werden muss: ein altes Postfach muss weiter aufgehen, ein
     * neues muss die neue Ableitung benutzen. Eine Testreihe, die nur die
     * neue Kette kennt, wuerde einen kaputten Altbestand nicht bemerken -
     * und genau der ist bei einer KDF-Migration der teure Fall.
     */
    unlock_chain_argon2id: UnlockChainMaterial;
}

/**
 * 8. key_transition.json - signierter Postfach-Schlüsselwechsel
 * (#658912ef, docs/VAULT_SCHLUESSELWECHSEL_SIGNATUR.md v2, Abschnitt 3).
 *
 * Jeder Fall trägt ALLES, was ein Prüfer braucht, um die Akte selbst zu
 * bauen und die Signatur zu prüfen - und `verify` sagt, was dabei
 * herauskommen MUSS. Die Negativfälle tragen dieselbe Signatur wie der
 * gültige Fall und ändern genau EIN Merkmal.
 */
export interface KeyTransitionCase {
    name: string;
    beschreibung: string;
    anlass: 1 | 2 | 3;
    anlass_name: 'rotation' | 'signierschluessel' | 'setup';
    /** Anmeldename in Aktenform (UTF-8-Bytes stehen in `record`). */
    login: string;
    old_x25519_public: string;
    old_mlkem_public: string;
    /** null = kein Signierschlüssel vor dem Wechsel (u32 0 im Preimage). */
    old_signing_public: string | null;
    /** Fingerabdruck v2 des alten Satzes (KEM + Signierschlüssel). */
    old_fingerprint_preimage: string;
    old_fingerprint_full: string;
    old_fingerprint_display: string;
    new_x25519_public: string;
    new_mlkem_public: string;
    new_signing_public: string;
    /** Der Schlüssel, GEGEN den geprüft wird (der alte Signierschlüssel). */
    signer_public: string;
    signed_at: number;
    /** Die Wechselakte (Vertrag 3.2). */
    record: string;
    context_utf8: string;
    /** ML-DSA-65, deterministisch (ohne Zusatzentropie) erzeugt. */
    signature: string;
    verify: boolean;
}

/** Einrichtungsakte (Vertrag 3.3): Nachweis von Master Key und neuem Seed. */
export interface KeyInstallCase {
    name: string;
    beschreibung: string;
    login: string;
    nonce: string;
    shared_secret: string;
    current_x25519_public: string;
    current_mlkem_public: string;
    current_signing_public: string | null;
    current_fingerprint_full: string;
    new_signing_public: string;
    /** Geprüft wird GEGEN den neuen Schlüssel. */
    signer_public: string;
    record: string;
    context_utf8: string;
    signature: string;
    verify: boolean;
}

/** Fingerabdruck v2 für sich, mit und ohne Signierschlüssel. */
export interface KeyFingerprintCase {
    name: string;
    x25519_public: string;
    mlkem_public: string;
    signing_public: string | null;
    preimage: string;
    full: string;
    display: string;
}

/** Privates Material, mit dem Clients den Rundlauf nachstellen können. */
export interface KeyTransitionMaterial {
    old_x25519_private: string;
    old_mlkem_seed: string;
    new_x25519_private: string;
    new_mlkem_seed: string;
    /** ξ (32 B) des ersten Signierschlüssels. */
    signer_seed: string;
    signer_public: string;
    /** ξ des zweiten Signierschlüssels (eingesetzt durch den Signierschlüsselwechsel). */
    signer2_seed: string;
    signer2_public: string;
    /** Ein Angreifer: eigener Signierschlüssel und eigener X25519-Schlüssel. */
    attacker_seed: string;
    attacker_public: string;
    attacker_x25519_private: string;
    /** AAD des Seed-Chiffrats (Vertrag 3.4) für `login`, als Hex und Text. */
    seed_aad: string;
    seed_aad_utf8: string;
}

export interface KeyPinShape {
    x25519_public: string;
    mlkem_public: string;
    /** null = ohne Signierschlüssel gemerkt (heutige Apple-Pins). */
    signing_public: string | null;
}

/**
 * Ein ganzer Kettenlauf (Vertrag 5): gepinnt ist `pin`, geliefert wird
 * `delivered` samt Kette; ein Client muss zu `expected` kommen.
 */
export interface KeyTransitionChainWalk {
    name: string;
    login: string;
    pin: KeyPinShape;
    delivered: KeyPinShape & {
        /** Namen der Fälle aus `cases`, älteste zuerst. */
        chain: string[];
    };
    expected: 'gleich' | 'uebernehmen' | 'halt';
    beschreibung: string;
}

export interface KeyTransitionFile {
    generator: GeneratorInfo;
    encoding: string;
    material: KeyTransitionMaterial;
    fingerprints: KeyFingerprintCase[];
    cases: KeyTransitionCase[];
    install_cases: KeyInstallCase[];
    chain_walks: KeyTransitionChainWalk[];
}
