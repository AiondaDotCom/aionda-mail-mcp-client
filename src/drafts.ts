/**
 * Entwürfe im Proxy: verschlüsseln, entschlüsseln, fortschreiben.
 *
 * Ein Entwurf ist JSON, AES-256-GCM-verschlüsselt mit dem Vault-Hauptschlüssel,
 * abgelegt als `iv_hex:ciphertext+tag_hex`. Genau dieses Format schreiben und
 * lesen der Web-Composer (`mailbox-composer.ts saveDraft`), die Apple-Apps
 * (`DraftContent.encode/decode`) und der Server für KI-Mitarbeiter. Ein
 * Entwurf, den eine KI hier anlegt, öffnet der Nutzer also im macOS-Client
 * und schreibt dort weiter - und umgekehrt.
 *
 * Bei einem persönlichen Schlüssel (Mensch) kennt der Server den
 * Hauptschlüssel nicht (Zero Knowledge). Darum verschlüsselt hier der Proxy
 * und schickt dem Server nur `encrypted_content`.
 */
import { decryptAesGcm, encryptClientAesGcm } from './crypto/aes-gcm';
import { fromHex, toHex } from './crypto/encoding';

export interface DraftAddress {
    email: string;
    name?: string;
}

/** Anhang im Entwurf - Schreibweise von Web-Composer und Apple-Apps. */
export interface DraftAttachment {
    id?: string;
    name: string;
    size: number;
    type: string;
    /** Base64 */
    content: string;
}

export interface DraftContent {
    subject?: string;
    body?: string;
    to?: DraftAddress[];
    cc?: DraftAddress[];
    bcc?: DraftAddress[];
    from_identity?: string;
    priority?: string;
    attachments?: DraftAttachment[];
    savedAt?: string;
    /** Felder anderer Erzeuger bleiben beim Fortschreiben erhalten. */
    [weitere: string]: unknown;
}

/** Felder, die eine KI beim Anlegen oder Fortschreiben setzen darf. */
export interface DraftChanges {
    subject?: unknown;
    body?: unknown;
    to?: unknown;
    cc?: unknown;
    bcc?: unknown;
    from_identity?: unknown;
}

const IV_LAENGE = 12;

/**
 * Adressfeld in die Objektliste bringen. Akzeptiert „a@x, b@y",
 * „Name <a@x>", eine Liste von Zeichenketten oder eine Objektliste.
 * Unlesbares wirft - eine Adresse verschwindet nie still.
 */
export function parseAddresses(value: unknown, feld: string): DraftAddress[] {
    if (value === undefined || value === null || value === '') return [];

    const teile: unknown[] = Array.isArray(value)
        ? value
        : typeof value === 'string'
            ? value.split(/[,;]/)
            : [value];

    const ergebnis: DraftAddress[] = [];
    for (const teil of teile) {
        if (teil && typeof teil === 'object') {
            const email = (teil as Record<string, unknown>).email;
            const name  = (teil as Record<string, unknown>).name;
            if (typeof email !== 'string' || !email.includes('@')) {
                throw new Error(`${feld}: entry without valid email`);
            }
            ergebnis.push(typeof name === 'string' && name.trim() !== ''
                ? { email: email.trim(), name: name.trim() }
                : { email: email.trim() });
            continue;
        }
        if (typeof teil !== 'string') {
            throw new Error(`${feld}: unsupported address value`);
        }
        const roh = teil.trim();
        if (roh === '') continue;
        const mitName = /^(.*)<([^<>\s]+@[^<>\s]+)>$/.exec(roh);
        if (mitName) {
            const name = mitName[1].trim().replace(/^"(.*)"$/, '$1').trim();
            ergebnis.push(name !== '' ? { email: mitName[2], name } : { email: mitName[2] });
        } else if (/^[^\s@]+@[^\s@]+$/.test(roh)) {
            ergebnis.push({ email: roh });
        } else {
            throw new Error(`${feld}: '${roh}' is not an email address`);
        }
    }
    return ergebnis;
}

/** Felder, die `clear_fields` ausdrücklich leeren darf. */
export const LEERBARE_FELDER = ['subject', 'body', 'to', 'cc', 'bcc', 'from_identity'] as const;

/** Leerer Wert = „nicht angegeben": Modelle schicken optionale Felder oft leer mit. */
function istLeer(wert: unknown): boolean {
    return wert === undefined || wert === null
        || (typeof wert === 'string' && wert.trim() === '')
        || (Array.isArray(wert) && wert.length === 0);
}

/**
 * Neuen Stand eines Entwurfs bilden. Nur übergebene Felder ändern sich;
 * alles andere (Anhänge, die der Nutzer im Client ergänzt hat, Priorität,
 * fremde Felder) bleibt erhalten. Neue Anhänge kommen dazu.
 *
 * Ein LEER übergebenes Feld ändert nichts - sonst würde ein Modell, das
 * `cc: ""` mitschickt, die Kopieempfänger des Nutzers löschen. Leeren geht
 * nur ausdrücklich über `leeren` (Werkzeugparameter `clear_fields`).
 */
export function mergeDraft(
    bisher: DraftContent,
    aenderung: DraftChanges,
    neueAnhaenge: DraftAttachment[],
    jetzt: Date = new Date(),
    leeren: readonly unknown[] = []
): DraftContent {
    const neu: DraftContent = { ...bisher };

    for (const feld of leeren) {
        if (!(LEERBARE_FELDER as readonly unknown[]).includes(feld)) {
            throw new Error(`clear_fields: '${String(feld)}' cannot be cleared (allowed: ${LEERBARE_FELDER.join(', ')})`);
        }
        if (!istLeer(aenderung[feld as keyof DraftChanges])) {
            throw new Error(`clear_fields: '${String(feld)}' is cleared and set at the same time`);
        }
    }

    for (const feld of ['subject', 'body', 'from_identity'] as const) {
        const wert = aenderung[feld];
        if (leeren.includes(feld)) { neu[feld] = ''; continue; }
        if (istLeer(wert)) continue;
        if (typeof wert !== 'string') throw new Error(`${feld} must be a string`);
        neu[feld] = wert;
    }
    for (const feld of ['to', 'cc', 'bcc'] as const) {
        if (leeren.includes(feld)) { neu[feld] = []; continue; }
        if (istLeer(aenderung[feld])) continue;
        const adressen = parseAddresses(aenderung[feld], feld);
        // „ , “ ergibt keine Adresse - das ist „leer“, nicht „leeren“ (wie der Server).
        if (adressen.length > 0) neu[feld] = adressen;
    }
    for (const feld of ['to', 'cc', 'bcc'] as const) {
        if (neu[feld] === undefined) neu[feld] = [];
    }
    if (neu.subject === undefined) neu.subject = '';
    if (neu.body === undefined) neu.body = '';

    if (neueAnhaenge.length > 0) {
        neu.attachments = [...(bisher.attachments ?? []), ...neueAnhaenge];
    }

    if ((neu.subject ?? '') === '' && (neu.body ?? '') === '') {
        throw new Error('subject or body is required');
    }

    neu.savedAt = jetzt.toISOString();
    return neu;
}

/** Entwurf verschlüsseln: `iv_hex:ciphertext+tag_hex`. */
export async function encryptDraft(inhalt: DraftContent, masterKey: Uint8Array): Promise<string> {
    const klar = new TextEncoder().encode(JSON.stringify(inhalt));
    const blob = await encryptClientAesGcm(klar, masterKey);
    return `${toHex(blob.slice(0, IV_LAENGE))}:${toHex(blob.slice(IV_LAENGE))}`;
}

/** Entwurf entschlüsseln. Wirft bei falschem Schlüssel oder kaputtem Format. */
export async function decryptDraft(geheim: string, masterKey: Uint8Array): Promise<DraftContent> {
    const treffer = /^([0-9a-fA-F]{24}):([0-9a-fA-F]+)$/.exec(geheim);
    if (!treffer) throw new Error('encrypted_content is not iv_hex:ciphertext_hex');
    const klar = await decryptAesGcm(fromHex(treffer[2]), masterKey, fromHex(treffer[1]));
    const inhalt = JSON.parse(new TextDecoder().decode(klar)) as unknown;
    if (!inhalt || typeof inhalt !== 'object' || Array.isArray(inhalt)) {
        throw new Error('draft plaintext is not a JSON object');
    }
    return inhalt as DraftContent;
}

/**
 * Was die KI von einem Entwurf zu sehen bekommt: alles außer den
 * Anhang-Nutzdaten (die würden den Kontext sprengen). Adressen als
 * lesbare Zeichenkette - so, wie save_draft sie wieder annimmt.
 */
export function draftForAi(meta: Record<string, unknown>, inhalt: DraftContent): Record<string, unknown> {
    const adressen = (liste?: DraftAddress[]): string =>
        (liste ?? []).map(a => (a.name ? `${a.name} <${a.email}>` : a.email)).join(', ');

    const { encrypted_content: _geheim, ...rest } = meta;
    return {
        ...rest,
        subject:       inhalt.subject ?? '',
        to:            adressen(inhalt.to),
        cc:            adressen(inhalt.cc),
        bcc:           adressen(inhalt.bcc),
        from_identity: inhalt.from_identity ?? '',
        body:          inhalt.body ?? '',
        attachments:   (inhalt.attachments ?? []).map(a => ({ name: a.name, size: a.size, type: a.type })),
        saved_at:      inhalt.savedAt ?? null,
    };
}
