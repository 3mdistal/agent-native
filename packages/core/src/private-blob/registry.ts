import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { uploadFile } from "../file-upload/index.js";
import {
  decryptSecretValue,
  encryptSecretValue,
  getSecretEncryptionKey,
} from "../secrets/crypto.js";
import type {
  PrivateBlobDeleteResult,
  PrivateBlobHandle,
  PrivateBlobProvider,
  PrivateBlobPutInput,
  PrivateBlobReadResult,
} from "./types.js";

interface PrivateBlobGlobals {
  __agentNativePrivateBlobProviders?: Map<string, PrivateBlobProvider>;
  __agentNativePrivateBlobPublicUploadFallback?: { enabled: boolean };
}

interface EncryptedPayload {
  iv: string;
  tag: string;
  ciphertext: Uint8Array;
}

interface EncryptionParams {
  iv: string;
  tag: string;
}

interface PublicUploadDescriptor {
  kind: "agent-native.private-blob.public-upload";
  version: 1;
  url: string;
  uploadProvider: string;
  uploadId?: string;
  encryption: EncryptionParams;
  mimeType?: string;
  metadata?: PrivateBlobHandle["metadata"];
  size: number;
  createdAt: string;
}

interface EncryptedPrivateBlobDescriptor {
  kind: "agent-native.private-blob.encrypted-provider";
  version: 1;
  underlying: PrivateBlobHandle;
  encryption: EncryptionParams;
  mimeType?: string;
  metadata?: PrivateBlobHandle["metadata"];
  size: number;
  createdAt: string;
}

const PUBLIC_UPLOAD_HANDLE_PREFIX = "public-upload:v1:";
const ENCRYPTED_PROVIDER_HANDLE_PREFIX = "encrypted-provider:v1:";
const globals = globalThis as typeof globalThis & PrivateBlobGlobals;
const providers: Map<string, PrivateBlobProvider> =
  (globals.__agentNativePrivateBlobProviders ??= new Map());
const publicUploadFallbackRef: { enabled: boolean } =
  (globals.__agentNativePrivateBlobPublicUploadFallback ??= {
    enabled: true,
  });

function toBytes(data: Uint8Array | Buffer): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

function encryptBytes(data: Uint8Array): EncryptedPayload {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getSecretEncryptionKey(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(data)),
    cipher.final(),
  ]);
  return {
    iv: iv.toString("base64url"),
    ciphertext: new Uint8Array(ciphertext),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

function decryptBytes(
  params: EncryptionParams,
  ciphertext: Uint8Array,
): Uint8Array {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    getSecretEncryptionKey(),
    Buffer.from(params.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(params.tag, "base64url"));
  return new Uint8Array(
    Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]),
  );
}

function encodePublicUploadDescriptor(
  descriptor: PublicUploadDescriptor,
): string {
  return `${PUBLIC_UPLOAD_HANDLE_PREFIX}${encryptSecretValue(
    JSON.stringify(descriptor),
  )}`;
}

function decodePublicUploadDescriptor(id: string): PublicUploadDescriptor {
  if (!id.startsWith(PUBLIC_UPLOAD_HANDLE_PREFIX)) {
    throw new Error(
      "Private blob handle is not a public-upload fallback handle",
    );
  }
  const raw = decryptSecretValue(id.slice(PUBLIC_UPLOAD_HANDLE_PREFIX.length));
  const descriptor = JSON.parse(raw) as PublicUploadDescriptor;
  if (
    descriptor?.kind !== "agent-native.private-blob.public-upload" ||
    descriptor.version !== 1 ||
    typeof descriptor.url !== "string"
  ) {
    throw new Error("Private blob handle descriptor is invalid");
  }
  return descriptor;
}

function isPublicUploadFallbackHandle(handle: PrivateBlobHandle): boolean {
  return handle.id.startsWith(PUBLIC_UPLOAD_HANDLE_PREFIX);
}

function encodeEncryptedProviderDescriptor(
  descriptor: EncryptedPrivateBlobDescriptor,
): string {
  return `${ENCRYPTED_PROVIDER_HANDLE_PREFIX}${encryptSecretValue(
    JSON.stringify(descriptor),
  )}`;
}

function decodeEncryptedProviderDescriptor(
  handle: PrivateBlobHandle,
): EncryptedPrivateBlobDescriptor {
  if (
    handle.provider !== "encrypted-private-blob" ||
    !handle.id.startsWith(ENCRYPTED_PROVIDER_HANDLE_PREFIX)
  )
    throw new Error("Private blob handle is not encrypted-provider storage");
  const raw = decryptSecretValue(
    handle.id.slice(ENCRYPTED_PROVIDER_HANDLE_PREFIX.length),
  );
  const value = JSON.parse(raw) as EncryptedPrivateBlobDescriptor;
  if (
    value?.kind !== "agent-native.private-blob.encrypted-provider" ||
    value.version !== 1 ||
    value.underlying?.opaque !== true ||
    typeof value.underlying.provider !== "string" ||
    typeof value.encryption?.iv !== "string" ||
    typeof value.encryption?.tag !== "string" ||
    !Number.isSafeInteger(value.size) ||
    value.size < 1
  )
    throw new Error("Encrypted private blob descriptor is invalid");
  return value;
}

async function putViaEncryptedPublicUpload(
  input: PrivateBlobPutInput,
): Promise<PrivateBlobHandle | null> {
  const bytes = toBytes(input.data);
  const encrypted = encryptBytes(bytes);
  const uploaded = await uploadFile({
    data: Buffer.from(encrypted.ciphertext),
    filename: input.filename ?? input.key ?? "private-blob.bin",
    mimeType: "application/octet-stream",
    ownerEmail: input.ownerEmail,
    recordAsset: false,
  });
  if (!uploaded) return null;

  const descriptor: PublicUploadDescriptor = {
    kind: "agent-native.private-blob.public-upload",
    version: 1,
    url: uploaded.url,
    uploadProvider: uploaded.provider,
    uploadId: uploaded.id,
    encryption: { iv: encrypted.iv, tag: encrypted.tag },
    mimeType: input.mimeType,
    metadata: input.metadata,
    size: bytes.byteLength,
    createdAt: new Date().toISOString(),
  };

  return {
    id: encodePublicUploadDescriptor(descriptor),
    provider: `public-upload:${uploaded.provider}`,
    opaque: true,
    encrypted: true,
    mimeType: input.mimeType,
    size: bytes.byteLength,
    createdAt: descriptor.createdAt,
    metadata: input.metadata,
  };
}

async function readViaEncryptedPublicUpload(
  handle: PrivateBlobHandle,
): Promise<PrivateBlobReadResult> {
  const descriptor = decodePublicUploadDescriptor(handle.id);
  const response = await fetch(descriptor.url);
  if (!response.ok) {
    throw new Error(
      `Private blob public-upload read failed (${response.status}): ${response.statusText}`,
    );
  }
  // The uploaded ciphertext is intentionally opaque; the descriptor carries
  // auth tag + IV separately so the backing public URL is useless by itself.
  const ciphertext = new Uint8Array(await response.arrayBuffer());
  return {
    data: decryptBytes(descriptor.encryption, ciphertext),
    mimeType: descriptor.mimeType,
    metadata: descriptor.metadata,
    handle,
  };
}

export function registerPrivateBlobProvider(
  provider: PrivateBlobProvider,
): void {
  providers.set(provider.id, provider);
}

export function unregisterPrivateBlobProvider(id: string): void {
  providers.delete(id);
}

export function listPrivateBlobProviders(): PrivateBlobProvider[] {
  return [...providers.values()];
}

export function getActivePrivateBlobProvider(): PrivateBlobProvider | null {
  for (const provider of providers.values()) {
    if (provider.isConfigured()) return provider;
  }
  return null;
}

export function setPrivateBlobPublicUploadFallbackEnabled(
  enabled: boolean,
): void {
  publicUploadFallbackRef.enabled = enabled;
}

export async function putPrivateBlob(
  input: PrivateBlobPutInput,
): Promise<PrivateBlobHandle | null> {
  const provider = getActivePrivateBlobProvider();
  if (provider) return provider.put(input);
  if (!publicUploadFallbackRef.enabled) return null;
  if (process.env.AGENT_NATIVE_PRIVATE_BLOB_PUBLIC_UPLOAD_FALLBACK === "0") {
    return null;
  }
  return putViaEncryptedPublicUpload(input);
}

/** Store bytes encrypted by the deployment key inside a configured private provider. */
export async function putEncryptedPrivateBlob(
  input: PrivateBlobPutInput,
): Promise<PrivateBlobHandle | null> {
  const provider = getActivePrivateBlobProvider();
  if (!provider) return null;
  const bytes = toBytes(input.data);
  const encrypted = encryptBytes(bytes);
  const underlying = await provider.put({
    ...input,
    data: encrypted.ciphertext,
    mimeType: "application/octet-stream",
    metadata: undefined,
  });
  const createdAt = new Date().toISOString();
  try {
    const descriptor: EncryptedPrivateBlobDescriptor = {
      kind: "agent-native.private-blob.encrypted-provider",
      version: 1,
      underlying,
      encryption: { iv: encrypted.iv, tag: encrypted.tag },
      mimeType: input.mimeType,
      metadata: input.metadata,
      size: bytes.byteLength,
      createdAt,
    };
    return {
      id: encodeEncryptedProviderDescriptor(descriptor),
      provider: "encrypted-private-blob",
      opaque: true,
      encrypted: true,
      mimeType: input.mimeType,
      size: bytes.byteLength,
      createdAt,
      metadata: input.metadata,
    };
  } catch (error) {
    await provider.delete(underlying).catch(() => undefined);
    throw error;
  }
}

export async function readEncryptedPrivateBlob(
  handle: PrivateBlobHandle,
): Promise<PrivateBlobReadResult> {
  const descriptor = decodeEncryptedProviderDescriptor(handle);
  const provider = providers.get(descriptor.underlying.provider);
  if (!provider || !provider.isConfigured())
    throw new Error("Encrypted private blob provider is unavailable");
  const stored = await provider.read(descriptor.underlying);
  const data = decryptBytes(descriptor.encryption, stored.data);
  if (data.byteLength !== descriptor.size)
    throw new Error("Encrypted private blob length mismatch");
  return {
    data,
    mimeType: descriptor.mimeType,
    metadata: descriptor.metadata,
    handle,
  };
}

export async function deleteEncryptedPrivateBlob(
  handle: PrivateBlobHandle,
): Promise<PrivateBlobDeleteResult> {
  const descriptor = decodeEncryptedProviderDescriptor(handle);
  const provider = providers.get(descriptor.underlying.provider);
  if (!provider || !provider.isConfigured())
    throw new Error("Encrypted private blob provider is unavailable");
  return provider.delete(descriptor.underlying);
}

export async function readPrivateBlob(
  handle: PrivateBlobHandle,
): Promise<PrivateBlobReadResult> {
  const provider = providers.get(handle.provider);
  if (provider) return provider.read(handle);
  if (isPublicUploadFallbackHandle(handle)) {
    return readViaEncryptedPublicUpload(handle);
  }
  throw new Error(`No private blob provider registered for ${handle.provider}`);
}

export async function deletePrivateBlob(
  handle: PrivateBlobHandle,
): Promise<PrivateBlobDeleteResult> {
  const provider = providers.get(handle.provider);
  if (provider) return provider.delete(handle);
  if (isPublicUploadFallbackHandle(handle)) {
    return {
      deleted: false,
      provider: handle.provider,
      reason:
        "delete is not supported by the encrypted public-upload fallback provider",
    };
  }
  throw new Error(`No private blob provider registered for ${handle.provider}`);
}
