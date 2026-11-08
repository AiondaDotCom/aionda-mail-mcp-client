/**
 * Real-time Event Types (SSE/Mercure)
 */

/**
 * Topic names are negotiated with the server. Keeping this type open lets an
 * older client ask for newer topics; the subscription response contains the
 * subset the connected server actually supports.
 */
export type EventType = string;

export interface EncryptedEventPayload {
    encrypted: string;
    x25519_ephemeral: string;
    mlkem_ciphertext: string;
    timestamp: number;
}

export interface DecryptedEvent<T = unknown> {
    type: EventType;
    data: T;
    timestamp: number;
    eventId?: string;
}

export interface EmailReceivedEventData {
    email_uuid: string;
    dea_address: string;
    folder_uuid?: string;
    is_read: boolean;
    has_vault: boolean;
}

export interface NotificationEventData {
    notification_uuid: string;
    type: string;
    reference_uuid?: string;
}

export interface EventSubscription {
    subscription_id: string;
    mercure_url: string;
    subscriber_jwt: string;
    topics: string[];
}

export interface MissedEventsOutput {
    events: EncryptedEventPayload[];
    has_more: boolean;
}

export type EventHandler<T = unknown> = (event: DecryptedEvent<T>) => void;
