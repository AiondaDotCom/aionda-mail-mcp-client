/**
 * MCP Error Hierarchy
 */

export class McpError extends Error {
    public readonly code: number;
    public readonly data?: unknown;

    constructor(message: string, code: number, data?: unknown) {
        super(message);
        this.name = 'McpError';
        this.code = code;
        this.data = data;
    }
}

export class McpAuthError extends McpError {
    constructor(message = 'Authentication failed') {
        super(message, 61);
        this.name = 'McpAuthError';
    }
}

export class McpRateLimitError extends McpError {
    public readonly retryAfterMs: number;

    constructor(message = 'Rate limit exceeded', retryAfterMs = 60000) {
        super(message, 429);
        this.name = 'McpRateLimitError';
        this.retryAfterMs = retryAfterMs;
    }
}

export class McpSessionExpiredError extends McpError {
    constructor(message = 'Session expired') {
        super(message, -32000);
        this.name = 'McpSessionExpiredError';
    }
}

export class McpToolError extends McpError {
    public readonly toolName: string;

    constructor(toolName: string, message: string, code: number) {
        super(message, code);
        this.name = 'McpToolError';
        this.toolName = toolName;
    }
}

export class McpDecryptionError extends McpError {
    constructor(message = 'Decryption failed') {
        super(message, 77);
        this.name = 'McpDecryptionError';
    }
}

// ── Server-Integrationen: Schlüsselgrenzen, Sperre, Idempotenz, Zeiger ──
//
// Quelle der Codes: includes/config.php des Servers (trashmail #359, #360).
// Jede Klasse sagt mit `retryable`, ob ein späterer Versuch mit DEMSELBEN
// Schlüssel und DENSELBEN Argumenten etwas ändern kann. `false` heißt:
// Wiederholen ist sinnlos, ein Mensch muss etwas tun (Schlüssel ersetzen,
// Sperre aufheben, Grenze ändern, Eingabe korrigieren).

/** Code 194–206 des Servers (`ERROR_CODE_MCP_*`). */
export const McpIntegrationErrorCodes = {
    KEY_SUSPENDED: 194,
    SOURCE_ADDRESS_DENIED: 195,
    FOLDER_NOT_ALLOWED: 196,
    MAIL_OUTSIDE_TIME_WINDOW: 197,
    SENDER_NOT_ALLOWED: 198,
    SEND_LIMIT_REACHED: 199,
    TOOL_NOT_ALLOWED: 200,
    IDEMPOTENCY_CONFLICT: 201,
    CURSOR_INVALID: 202,
    KEY_ROTATED: 203,
    LIMIT_ABOVE_ACCOUNT: 204,
    KEY_COMPANY_MANAGED: 205,
    LIMIT_LOOSENED: 206,
} as const;

/** Basis aller Fehler mit Server-Code 194–206. `code` ist der Server-Code. */
export class McpIntegrationError extends McpError {
    /** Werkzeug, bei dem der Fehler auftrat (fehlt bei Ablehnung schon bei der Anmeldung). */
    public readonly toolName?: string;
    /** Kann ein späterer, gleicher Versuch gelingen? */
    public readonly retryable: boolean;

    constructor(message: string, code: number, retryable: boolean, toolName?: string, data?: unknown) {
        super(message, code, data);
        this.name = 'McpIntegrationError';
        this.retryable = retryable;
        this.toolName = toolName;
    }
}

/**
 * Der Schlüssel selbst ist unbrauchbar: gesperrt (194) oder durch einen
 * Nachfolger abgelöst (203). Jeder weitere Aufruf mit ihm scheitert genauso –
 * nicht wiederholen, sondern Alarm geben und den Schlüssel austauschen.
 */
export class McpKeyUnusableError extends McpIntegrationError {
    constructor(message: string, code: number, toolName?: string, data?: unknown) {
        super(message, code, false, toolName, data);
        this.name = 'McpKeyUnusableError';
    }
}

/** 194: Sofortsperre (vom Kontoinhaber oder von der Firma). Nur ein Mensch hebt sie auf. */
export class McpKeySuspendedError extends McpKeyUnusableError {
    constructor(message = 'This MCP key is suspended', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.KEY_SUSPENDED, toolName, data);
        this.name = 'McpKeySuspendedError';
    }
}

/** 203: Der Schlüssel wurde rotiert, der Nachfolger ist benutzt worden; der alte ist abgelaufen. */
export class McpKeyRotatedError extends McpKeyUnusableError {
    constructor(message = 'This MCP key was replaced by a new key and has expired', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.KEY_ROTATED, toolName, data);
        this.name = 'McpKeyRotatedError';
    }
}

/**
 * 195–200: Der Aufruf liegt außerhalb der festen Grenzen dieses Schlüssels.
 * Der Server liefert dann nie ein Teilergebnis. Bis auf die Versandgrenze
 * (199) ändert ein Wiederholen nichts.
 */
export class McpKeyLimitError extends McpIntegrationError {
    constructor(message: string, code: number, retryable: boolean, toolName?: string, data?: unknown) {
        super(message, code, retryable, toolName, data);
        this.name = 'McpKeyLimitError';
    }
}

/** 195: Aufruf von einer Quelladresse außerhalb von `allowed_source_ips`. */
export class McpSourceAddressDeniedError extends McpKeyLimitError {
    constructor(message = 'This MCP key may not be used from this source address', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.SOURCE_ADDRESS_DENIED, false, toolName, data);
        this.name = 'McpSourceAddressDeniedError';
    }
}

/** 196: Ordner außerhalb von `allowed_folders`. */
export class McpFolderNotAllowedError extends McpKeyLimitError {
    constructor(message = 'Folder is not allowed for this MCP key', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.FOLDER_NOT_ALLOWED, false, toolName, data);
        this.name = 'McpFolderNotAllowedError';
    }
}

/** 197: Mail älter als das Zeitfenster `max_age_days`. */
export class McpOutsideTimeWindowError extends McpKeyLimitError {
    constructor(message = 'Email is outside the time window of this MCP key', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.MAIL_OUTSIDE_TIME_WINDOW, false, toolName, data);
        this.name = 'McpOutsideTimeWindowError';
    }
}

/** 198: Absenderadresse nicht in `allowed_senders`. */
export class McpSenderNotAllowedError extends McpKeyLimitError {
    constructor(message = 'Sender address is not allowed for this MCP key', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.SENDER_NOT_ALLOWED, false, toolName, data);
        this.name = 'McpSenderNotAllowedError';
    }
}

/**
 * 199: Versandgrenze je Stunde oder Tag erreicht; es wurde nichts gesendet.
 * Wiederholen ist sinnvoll, aber erst wenn das Fenster weitergerückt ist.
 */
export class McpSendLimitReachedError extends McpKeyLimitError {
    constructor(message = 'Send limit of this MCP key reached', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.SEND_LIMIT_REACHED, true, toolName, data);
        this.name = 'McpSendLimitReachedError';
    }
}

/**
 * 200: Werkzeug für diesen Schlüssel gesperrt – nicht in `allowed_tools`,
 * oder bei einer Ordner-/Zeitgrenze gesperrt, weil es die Grenze nicht prüfen
 * kann (z. B. `event_subscribe`, `get_missed_events`, `share_folder`).
 */
export class McpToolNotAllowedError extends McpKeyLimitError {
    constructor(message = 'Tool is not allowed for this MCP key', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.TOOL_NOT_ALLOWED, false, toolName, data);
        this.name = 'McpToolNotAllowedError';
    }
}

/**
 * 201: `idempotency_key` kollidiert. Es wurde in keinem Fall eine zweite
 * Mail gesendet. Zwei Fälle:
 *   - `inProgress === true`: der erste Auftrag läuft noch (oder sein Zustand
 *     änderte sich gerade). Später mit demselben Schlüssel wiederholen.
 *   - sonst: derselbe Schlüssel wurde binnen 24 h für einen ANDEREN Auftrag
 *     benutzt – Wiederholen ist sinnlos.
 *
 * 🚩 Der Server kennt ein Feld `in_progress`, reicht es über MCP aber nicht
 *    weiter (nur `error_code` und `message`). Die Unterscheidung beruht
 *    deshalb auf dem Wortlaut der Servermeldung; unbekannter Wortlaut gilt
 *    als „anderer Auftrag“ (nicht wiederholen).
 */
export class McpIdempotencyConflictError extends McpIntegrationError {
    public readonly inProgress: boolean;

    constructor(message = 'idempotency_key conflict', toolName?: string, data?: unknown) {
        const inProgress = McpIdempotencyConflictError.isInProgressMessage(message, data);
        super(message, McpIntegrationErrorCodes.IDEMPOTENCY_CONFLICT, inProgress, toolName, data);
        this.name = 'McpIdempotencyConflictError';
        this.inProgress = inProgress;
    }

    static isInProgressMessage(message: string, data?: unknown): boolean {
        if (data && typeof data === 'object' && (data as Record<string, unknown>).in_progress === true) return true;
        return /still in progress|changed state concurrently/i.test(message);
    }
}

/**
 * 202: Der Zeiger (`after`) ist für dieses Postfach unbekannt, meist weil die
 * Mail gelöscht wurde. Mit `after = "start"` neu beginnen und auf eigener
 * Seite nach Mail-UUID entdoppeln.
 */
export class McpCursorInvalidError extends McpIntegrationError {
    constructor(message = 'Cursor is unknown for this mailbox', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.CURSOR_INVALID, false, toolName, data);
        this.name = 'McpCursorInvalidError';
    }
}

/** 204–206: Abgelehnte Verwaltung von Schlüsselgrenzen. Eingabe korrigieren. */
export class McpKeyAdminError extends McpIntegrationError {
    constructor(message: string, code: number, toolName?: string, data?: unknown) {
        super(message, code, false, toolName, data);
        this.name = 'McpKeyAdminError';
    }
}

/** 204: Grenze über der Kontogrenze (30 Mails/Tag) – sie würde die Kontogrenze anheben. */
export class McpLimitAboveAccountError extends McpKeyAdminError {
    constructor(message = 'Key limit is above the account limit', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.LIMIT_ABOVE_ACCOUNT, toolName, data);
        this.name = 'McpLimitAboveAccountError';
    }
}

/** 205: Grenzen bzw. Sperre setzt die Firma; der Schlüsselinhaber kann sie nicht lockern. */
export class McpKeyCompanyManagedError extends McpKeyAdminError {
    constructor(message = 'The limits of this MCP key are managed by the company', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.KEY_COMPANY_MANAGED, toolName, data);
        this.name = 'McpKeyCompanyManagedError';
    }
}

/** 206: Ein Firmeneingriff würde eine Grenze lockern statt verschärfen. */
export class McpLimitLoosenedError extends McpKeyAdminError {
    constructor(message = 'The company can only tighten limits', toolName?: string, data?: unknown) {
        super(message, McpIntegrationErrorCodes.LIMIT_LOOSENED, toolName, data);
        this.name = 'McpLimitLoosenedError';
    }
}

/** Server-Code der Anmeldesperre nach 20 Fehlversuchen in 15 Minuten. */
const ERROR_CODE_RATE_LIMIT = 78;
const ERROR_CODE_AUTHENTICATION_ERROR = 61;

/**
 * Anwendungsfehler des Servers in die passende Klasse übersetzen.
 *
 * `code` ist der Server-Code (`error_code`), nicht der JSON-RPC-Code.
 * Unbekannte Codes werden zu `McpToolError` (mit Werkzeug) bzw. `McpError`.
 */
export function mcpErrorFromCode(code: number, message: string, toolName?: string, data?: unknown): McpError {
    const C = McpIntegrationErrorCodes;
    switch (code) {
        case C.KEY_SUSPENDED: return new McpKeySuspendedError(message, toolName, data);
        case C.KEY_ROTATED: return new McpKeyRotatedError(message, toolName, data);
        case C.SOURCE_ADDRESS_DENIED: return new McpSourceAddressDeniedError(message, toolName, data);
        case C.FOLDER_NOT_ALLOWED: return new McpFolderNotAllowedError(message, toolName, data);
        case C.MAIL_OUTSIDE_TIME_WINDOW: return new McpOutsideTimeWindowError(message, toolName, data);
        case C.SENDER_NOT_ALLOWED: return new McpSenderNotAllowedError(message, toolName, data);
        case C.SEND_LIMIT_REACHED: return new McpSendLimitReachedError(message, toolName, data);
        case C.TOOL_NOT_ALLOWED: return new McpToolNotAllowedError(message, toolName, data);
        case C.IDEMPOTENCY_CONFLICT: return new McpIdempotencyConflictError(message, toolName, data);
        case C.CURSOR_INVALID: return new McpCursorInvalidError(message, toolName, data);
        case C.LIMIT_ABOVE_ACCOUNT: return new McpLimitAboveAccountError(message, toolName, data);
        case C.KEY_COMPANY_MANAGED: return new McpKeyCompanyManagedError(message, toolName, data);
        case C.LIMIT_LOOSENED: return new McpLimitLoosenedError(message, toolName, data);
        case ERROR_CODE_RATE_LIMIT: return new McpRateLimitError(message);
        case ERROR_CODE_AUTHENTICATION_ERROR: return new McpAuthError(message);
        default:
            return toolName !== undefined ? new McpToolError(toolName, message, code) : new McpError(message, code, data);
    }
}

/**
 * JSON-RPC-Fehlerobjekt übersetzen. Ablehnungen am Schlüsseltor (Sperre,
 * Quelladresse, Rotation) kommen als `{code: -32000, data: {error_code}}`.
 * Ohne `data.error_code` bleibt es ein `McpError` mit dem JSON-RPC-Code.
 */
export function mcpErrorFromJsonRpc(
    error: { code: number; message?: string; data?: unknown },
    toolName?: string
): McpError {
    const data = error.data as Record<string, unknown> | undefined;
    const appCode = data && typeof data.error_code === 'number' ? data.error_code : undefined;
    const message = error.message || `Server error ${error.code}`;
    if (appCode === undefined) return new McpError(message, error.code, error.data);
    return mcpErrorFromCode(appCode, message, toolName, error.data);
}

/**
 * Darf ein Aufrufer denselben Aufruf später wiederholen?
 *
 * true: Ratenbegrenzung, Versandgrenze (199), Idempotenz „in Arbeit“ (201),
 *       Zeitüberschreitung/Netzfehler des Transports.
 * false: alles andere, insbesondere gesperrte/abgelöste Schlüssel.
 */
export function isRetryableMcpError(error: unknown): boolean {
    if (error instanceof McpIntegrationError) return error.retryable;
    if (error instanceof McpRateLimitError) return true;
    if (error instanceof McpTransportError) return true;
    return false;
}

/** Zeitüberschreitung oder Netzfehler – der Server hat (vielleicht) nie geantwortet. */
export class McpTransportError extends McpError {
    constructor(message: string, code = -32603) {
        super(message, code);
        this.name = 'McpTransportError';
    }
}
