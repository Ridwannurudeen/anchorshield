import type { CliProof, EligibilityAction } from "./index";

export type AnchorShieldStatus =
  | "idle"
  | "connecting"
  | "connected"
  | "submitting"
  | "submitted"
  | "pending"
  | "error";

export interface FreighterApi {
  isConnected?: () => Promise<{ error?: { message?: string } | string }>;
  requestAccess: () => Promise<{
    address?: string;
    error?: { message?: string } | string;
  }>;
  signTransaction: (...args: unknown[]) => unknown;
}

export interface AnchorShieldHookOptions {
  stellarSdk?: unknown;
  freighterApi?: FreighterApi;
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  sourceAddress?: string;
  specEntries?: string[];
  fee?: string;
  timeout?: number;
  pollIntervalMs?: number;
  pollAttempts?: number;
}

export interface SubmitPaymentProofRequest extends AnchorShieldHookOptions {
  proof: CliProof;
  publicSignals: unknown;
  action: EligibilityAction;
}

export interface UseAnchorShieldResult {
  address: string;
  status: AnchorShieldStatus;
  error: Error | null;
  result: unknown;
  connect: () => Promise<string>;
  submitPaymentProof: (request: SubmitPaymentProofRequest) => Promise<unknown>;
}

export interface AnchorShieldGateProps extends AnchorShieldHookOptions {
  proof: CliProof;
  publicSignals: unknown;
  action: EligibilityAction;
  specEntries?: string[];
  disabled?: boolean;
  pendingLabel?: string;
  buttonProps?: Record<string, unknown>;
  children?: unknown | ((state: UseAnchorShieldResult) => unknown);
  onSuccess?: (result: unknown) => void;
  onError?: (error: Error) => void;
}

export function requestWalletAccess(
  freighterApi: FreighterApi,
): Promise<string>;
export function useAnchorShield(
  options?: AnchorShieldHookOptions,
): UseAnchorShieldResult;
export function AnchorShieldGate(props: AnchorShieldGateProps): unknown;
