export type DecimalString = string;
export type ByteBuffer = Uint8Array;
export type PublicSignalName =
  | "credential_root"
  | "packet_hash"
  | "nullifier"
  | "action_binding"
  | "issuer_id"
  | "policy_id"
  | "kyc_required"
  | "sanctions_required"
  | "allowed_country"
  | "min_age"
  | "min_investor_type"
  | "action_type"
  | "asset_id"
  | "amount"
  | "recipient"
  | "action_id"
  | "epoch"
  | "sanctions_root"
  | "revocation_root";

export type EligibilityPublicSignals = Record<PublicSignalName, DecimalString>;

export interface SorobanU256 {
  u256: DecimalString;
}

export interface EligibilityAction {
  issuer_id: DecimalString | number | bigint;
  policy_id: DecimalString | number | bigint;
  kyc_required: DecimalString | number | bigint;
  sanctions_required: DecimalString | number | bigint;
  allowed_country: DecimalString | number | bigint;
  min_age: DecimalString | number | bigint;
  min_investor_type: DecimalString | number | bigint;
  action_type: DecimalString | number | bigint;
  asset_id: DecimalString | number | bigint;
  amount: DecimalString | number | bigint;
  recipient: DecimalString | number | bigint;
  action_id: DecimalString | number | bigint;
  epoch: DecimalString | number | bigint;
  sanctions_root: DecimalString | number | bigint;
  revocation_root: DecimalString | number | bigint;
}

export interface CliProof {
  a: string;
  b: string;
  c: string;
}

export interface CliVerificationKey {
  alpha: string;
  beta: string;
  gamma: string;
  delta: string;
  ic: string[];
}

export interface CliArgs {
  vk: CliVerificationKey;
  proof: CliProof;
  pub_signals: SorobanU256[];
}

export interface BindingProof {
  a: ByteBuffer;
  b: ByteBuffer;
  c: ByteBuffer;
}

export interface BindingVerificationKey {
  alpha: ByteBuffer;
  beta: ByteBuffer;
  gamma: ByteBuffer;
  delta: ByteBuffer;
  ic: ByteBuffer[];
}

export interface BindingArgs {
  vk: BindingVerificationKey;
  proof: BindingProof;
  pub_signals: bigint[];
}

export interface PaymentInvokeArgs extends BindingArgs {
  policy_id: number;
  asset_id: number;
  amount: bigint;
  recipient_id: bigint;
  action_id: bigint;
  packet_hash: bigint;
  epoch: number;
}

export interface RwaInvokeArgs extends BindingArgs {
  policy_id: number;
  asset_id: number;
  amount: bigint;
  recipient: bigint;
  action_id: bigint;
  terms_hash: bigint;
  epoch: number;
}

export const ACTION_FIELDS: readonly PublicSignalName[];
export const PAYMENT_ACTION_TYPE: "0";
export const PUBLIC_SIGNAL_INDEX: Readonly<Record<PublicSignalName, number>>;
export const PUBLIC_SIGNAL_NAMES: readonly PublicSignalName[];
export const RWA_ACTION_TYPE: "1";

export function readJson(file: string): unknown;
export function writeJson(file: string, value: unknown): void;
export function createProofRequest(args: {
  input: Record<string, unknown>;
  overrides?: Record<string, DecimalString | number | bigint>;
}): { input: Record<string, unknown>; action: EligibilityAction };
export function normalizePublicSignals(value: unknown): DecimalString[];
export function parsePublicSignals(publicSignals: unknown): EligibilityPublicSignals;
export function formatSorobanPubSignals(publicSignals: unknown): SorobanU256[];
export function formatImplicitCliPubSignals(publicSignals: unknown): DecimalString[];
export function formatBindingPubSignals(publicSignals: unknown): bigint[];
export function assertActionMatchesPublicSignals(
  action: EligibilityAction,
  publicSignals: unknown,
): EligibilityPublicSignals;
export function assertPaymentAction(
  action: EligibilityAction,
  publicSignals: unknown,
): EligibilityPublicSignals;
export function assertRwaAction(
  action: EligibilityAction,
  publicSignals: unknown,
): EligibilityPublicSignals;
export function formatBindingProof(proof: CliProof): BindingProof;
export function formatBindingVerificationKey(vk: CliVerificationKey): BindingVerificationKey;
export function cliArgsToBindingArgs(cliArgs: CliArgs): BindingArgs;
export function buildPaymentInvokeArgs(cliArgs: CliArgs, action: EligibilityAction): PaymentInvokeArgs;
export function buildRwaInvokeArgs(cliArgs: CliArgs, action: EligibilityAction): RwaInvokeArgs;
export function stellarExpertTxUrl(network: string, txHash: string): string;
export function paymentContractArgs(args: {
  proof: CliProof;
  publicSignals: unknown;
  action: EligibilityAction;
}): Omit<PaymentInvokeArgs, "vk">;
export function generateProof(args: {
  input: unknown;
  wasmPath: string;
  zkeyPath: string;
}): Promise<{ proof: unknown; publicSignals: DecimalString[] }>;
export function prove(args: {
  input: unknown;
  wasmPath: string;
  zkeyPath: string;
  verificationKey?: unknown;
}): Promise<{ proof: unknown; publicSignals: DecimalString[] }>;
export function verifyProof(args: {
  verificationKey: unknown;
  proof: unknown;
  publicSignals: unknown;
}): Promise<boolean>;
export function submitPaymentProof(args: {
  stellarSdk?: unknown;
  freighterApi: { signTransaction: Function };
  rpcUrl?: string;
  networkPassphrase: string;
  contractId: string;
  sourceAddress: string;
  proof: CliProof;
  publicSignals: unknown;
  action: EligibilityAction;
  specEntries: string[];
  fee?: string;
  timeout?: number;
  pollIntervalMs?: number;
  pollAttempts?: number;
}): Promise<{ txHash: string; status: string; result?: unknown; submitted: unknown }>;
