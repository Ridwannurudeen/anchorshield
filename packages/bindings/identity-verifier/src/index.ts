import { Buffer } from "buffer";
import { Address } from "@stellar/stellar-sdk";
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Timepoint,
  Duration,
} from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";

if (typeof window !== "undefined") {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}

export const Errors = {
  1: { message: "AlreadyInitialized" },
  2: { message: "NotInitialized" },
  3: { message: "MissingPolicy" },
  4: { message: "MissingRoot" },
  5: { message: "MalformedPublicSignals" },
  6: { message: "PublicInputMismatch" },
  7: { message: "RootMismatch" },
  8: { message: "NullifierUsed" },
  9: { message: "InvalidProof" },
  10: { message: "MalformedVerifyingKey" },
  11: { message: "NotEligible" },
  12: { message: "Expired" },
  13: { message: "MissingSanctionsRoot" },
  14: { message: "MissingRevocationRoot" },
  15: { message: "SanctionsRootMismatch" },
  16: { message: "RevocationRootMismatch" },
  17: { message: "Paused" },
  18: { message: "CircuitMismatch" },
  19: { message: "AlreadySet" },
  20: { message: "BadAmount" },
  21: { message: "MissingToken" },
  22: { message: "MissingRecipient" },
  23: { message: "RecipientMismatch" },
  24: { message: "MintConsumerNotAllowed" },
  25: { message: "MissingMintAuthorization" },
  26: { message: "AmountMismatch" },
  27: { message: "AnonymitySetTooSmall" },
  28: { message: "NotPauser" },
  29: { message: "NoPendingAdmin" },
};

export interface MintAuthorization {
  action_binding: Buffer;
  action_id: u128;
  amount: i128;
  nullifier: Buffer;
  terms_hash: Buffer;
  valid_until: u64;
}

export interface Proof {
  a: Buffer;
  b: Buffer;
  c: Buffer;
}

export interface Policy {
  allowed_country: u32;
  circuit_id: Buffer;
  circuit_version: u32;
  issuer_id: u32;
  kyc_required: boolean;
  min_age: u32;
  min_credential_members: u32;
  min_investor_type: u32;
  policy_id: u32;
  sanctions_required: boolean;
}

export interface VerificationKey {
  alpha: Buffer;
  beta: Buffer;
  delta: Buffer;
  gamma: Buffer;
  ic: Array<Buffer>;
}

export interface Client {
  /**
   * Construct and simulate a init transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  init: (
    {
      admin,
      verifier,
      issuer_registry,
      policy_registry,
      nullifier_registry,
    }: {
      admin: string;
      verifier: string;
      issuer_registry: string;
      policy_registry: string;
      nullifier_registry: string;
    },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a pause transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  pause: (
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a attest transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Record an eligibility attestation for `account` (who must authorize the
   * call) from a valid ZK proof. `valid_until` is a ledger timestamp.
   */
  attest: (
    {
      account,
      proof,
      pub_signals,
      policy_id,
      epoch,
      valid_until,
    }: {
      account: string;
      proof: Proof;
      pub_signals: Array<u256>;
      policy_id: u32;
      epoch: u32;
      valid_until: u64;
    },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a paused transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  paused: (options?: MethodOptions) => Promise<AssembledTransaction<boolean>>;

  /**
   * Construct and simulate a unpause transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  unpause: (
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a rwa_token transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  rwa_token: (
    { asset_id }: { asset_id: u32 },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<string>>>;

  /**
   * Construct and simulate a rwa_recipient transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  rwa_recipient: (
    { recipient_id }: { recipient_id: u128 },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<string>>>;

  /**
   * Construct and simulate a set_rwa_token transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_rwa_token: (
    { asset_id, token }: { asset_id: u32; token: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a attest_for_mint transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  attest_for_mint: (
    {
      account,
      consumer,
      proof,
      pub_signals,
      policy_id,
      asset_id,
      amount,
      recipient_id,
      action_id,
      terms_hash,
      epoch,
      valid_until,
    }: {
      account: string;
      consumer: string;
      proof: Proof;
      pub_signals: Array<u256>;
      policy_id: u32;
      asset_id: u32;
      amount: i128;
      recipient_id: u128;
      action_id: u128;
      terms_hash: u256;
      epoch: u32;
      valid_until: u64;
    },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a recovery_target transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * IdentityVerifier interface method. AnchorShield does not implement account
   * recovery, so there is never a recovery target.
   */
  recovery_target: (
    { old_account }: { old_account: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<string>>>;

  /**
   * Construct and simulate a verify_identity transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Called by the SEP-57 RWA token before mint/transfer. Succeeds only while a
   * non-expired attestation exists for `account`; otherwise traps, reverting the
   * token operation.
   */
  verify_identity: (
    { account }: { account: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a set_rwa_recipient transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_rwa_recipient: (
    { recipient_id, account }: { recipient_id: u128; account: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a attestation_expiry transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  attestation_expiry: (
    { account }: { account: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<u64>>>;

  /**
   * Construct and simulate a mint_authorization transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  mint_authorization: (
    {
      consumer,
      token,
      account,
    }: { consumer: string; token: string; account: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<MintAuthorization>>>;

  /**
   * Construct and simulate a allow_mint_consumer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  allow_mint_consumer: (
    { consumer }: { consumer: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a revoke_mint_consumer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  revoke_mint_consumer: (
    { consumer }: { consumer: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a is_mint_consumer_allowed transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  is_mint_consumer_allowed: (
    { consumer }: { consumer: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<boolean>>;

  /**
   * Construct and simulate a consume_mint_authorization transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  consume_mint_authorization: (
    {
      consumer,
      token,
      account,
      amount,
    }: { consumer: string; token: string; account: string; amount: i128 },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;
}
export class Client extends ContractClient {
  static async deploy<T = Client>(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      },
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(null, options);
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAGgAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAABAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAgAAAAAAAAANTWlzc2luZ1BvbGljeQAAAAAAAAMAAAAAAAAAC01pc3NpbmdSb290AAAAAAQAAAAAAAAAFk1hbGZvcm1lZFB1YmxpY1NpZ25hbHMAAAAAAAUAAAAAAAAAE1B1YmxpY0lucHV0TWlzbWF0Y2gAAAAABgAAAAAAAAAMUm9vdE1pc21hdGNoAAAABwAAAAAAAAANTnVsbGlmaWVyVXNlZAAAAAAAAAgAAAAAAAAADEludmFsaWRQcm9vZgAAAAkAAAAAAAAAFU1hbGZvcm1lZFZlcmlmeWluZ0tleQAAAAAAAAoAAAAAAAAAC05vdEVsaWdpYmxlAAAAAAsAAAAAAAAAB0V4cGlyZWQAAAAADAAAAAAAAAAUTWlzc2luZ1NhbmN0aW9uc1Jvb3QAAAANAAAAAAAAABVNaXNzaW5nUmV2b2NhdGlvblJvb3QAAAAAAAAOAAAAAAAAABVTYW5jdGlvbnNSb290TWlzbWF0Y2gAAAAAAAAPAAAAAAAAABZSZXZvY2F0aW9uUm9vdE1pc21hdGNoAAAAAAAQAAAAAAAAAAZQYXVzZWQAAAAAABEAAAAAAAAAD0NpcmN1aXRNaXNtYXRjaAAAAAASAAAAAAAAAApBbHJlYWR5U2V0AAAAAAATAAAAAAAAAAlCYWRBbW91bnQAAAAAAAAUAAAAAAAAAAxNaXNzaW5nVG9rZW4AAAAVAAAAAAAAABBNaXNzaW5nUmVjaXBpZW50AAAAFgAAAAAAAAARUmVjaXBpZW50TWlzbWF0Y2gAAAAAAAAXAAAAAAAAABZNaW50Q29uc3VtZXJOb3RBbGxvd2VkAAAAAAAYAAAAAAAAABhNaXNzaW5nTWludEF1dGhvcml6YXRpb24AAAAZAAAAAAAAAA5BbW91bnRNaXNtYXRjaAAAAAAAGg==",
        "AAAABQAAAAAAAAAAAAAABlBhdXNlZAAAAAAAAgAAAAhpZGVudGl0eQAAAAZwYXVzZWQAAAAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAACFVucGF1c2VkAAAAAgAAAAhpZGVudGl0eQAAAAh1bnBhdXNlZAAAAAAAAAAC",
        "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",
        "AAAAAAAAAAAAAAANcndhX3JlY2lwaWVudAAAAAAAAAEAAAAAAAAADHJlY2lwaWVudF9pZAAAAAoAAAABAAAD6AAAABM=",
        "AAAAAAAAAAAAAAANc2V0X3J3YV90b2tlbgAAAAAAAAIAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAPYXR0ZXN0X2Zvcl9taW50AAAAAAwAAAAAAAAAB2FjY291bnQAAAAAEwAAAAAAAAAIY29uc3VtZXIAAAATAAAAAAAAAAVwcm9vZgAAAAAAB9AAAAAFUHJvb2YAAAAAAAAAAAAAC3B1Yl9zaWduYWxzAAAAA+oAAAAMAAAAAAAAAAlwb2xpY3lfaWQAAAAAAAAEAAAAAAAAAAhhc3NldF9pZAAAAAQAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAMcmVjaXBpZW50X2lkAAAACgAAAAAAAAAJYWN0aW9uX2lkAAAAAAAACgAAAAAAAAAKdGVybXNfaGFzaAAAAAAADAAAAAAAAAAFZXBvY2gAAAAAAAAEAAAAAAAAAAt2YWxpZF91bnRpbAAAAAAGAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAHlJZGVudGl0eVZlcmlmaWVyIGludGVyZmFjZSBtZXRob2QuIEFuY2hvclNoaWVsZCBkb2VzIG5vdCBpbXBsZW1lbnQgYWNjb3VudApyZWNvdmVyeSwgc28gdGhlcmUgaXMgbmV2ZXIgYSByZWNvdmVyeSB0YXJnZXQuAAAAAAAAD3JlY292ZXJ5X3RhcmdldAAAAAABAAAAAAAAAAtvbGRfYWNjb3VudAAAAAATAAAAAQAAA+gAAAAT",
        "AAAAAAAAAKhDYWxsZWQgYnkgdGhlIFNFUC01NyBSV0EgdG9rZW4gYmVmb3JlIG1pbnQvdHJhbnNmZXIuIFN1Y2NlZWRzIG9ubHkgd2hpbGUgYQpub24tZXhwaXJlZCBhdHRlc3RhdGlvbiBleGlzdHMgZm9yIGBhY2NvdW50YDsgb3RoZXJ3aXNlIHRyYXBzLCByZXZlcnRpbmcgdGhlCnRva2VuIG9wZXJhdGlvbi4AAAAPdmVyaWZ5X2lkZW50aXR5AAAAAAEAAAAAAAAAB2FjY291bnQAAAAAEwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAARc2V0X3J3YV9yZWNpcGllbnQAAAAAAAACAAAAAAAAAAxyZWNpcGllbnRfaWQAAAAKAAAAAAAAAAdhY2NvdW50AAAAABMAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAASYXR0ZXN0YXRpb25fZXhwaXJ5AAAAAAABAAAAAAAAAAdhY2NvdW50AAAAABMAAAABAAAD6AAAAAY=",
        "AAAAAAAAAAAAAAASbWludF9hdXRob3JpemF0aW9uAAAAAAADAAAAAAAAAAhjb25zdW1lcgAAABMAAAAAAAAABXRva2VuAAAAAAAAEwAAAAAAAAAHYWNjb3VudAAAAAATAAAAAQAAA+gAAAfQAAAAEU1pbnRBdXRob3JpemF0aW9uAAAA",
        "AAAAAAAAAAAAAAATYWxsb3dfbWludF9jb25zdW1lcgAAAAABAAAAAAAAAAhjb25zdW1lcgAAABMAAAABAAAD6QAAAAIAAAAD",
        "AAAABQAAAAAAAAAAAAAAHFJ3YU1pbnRBdXRob3JpemF0aW9uQ29uc3VtZWQAAAACAAAACGlkZW50aXR5AAAADW1pbnRfY29uc3VtZWQAAAAAAAAEAAAAAAAAAAhjb25zdW1lcgAAABMAAAAAAAAAAAAAAAV0b2tlbgAAAAAAABMAAAAAAAAAAAAAAAdhY2NvdW50AAAAABMAAAAAAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAAAg==",
        "AAAAAAAAAAAAAAAUcmV2b2tlX21pbnRfY29uc3VtZXIAAAABAAAAAAAAAAhjb25zdW1lcgAAABMAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAAYaXNfbWludF9jb25zdW1lcl9hbGxvd2VkAAAAAQAAAAAAAAAIY29uc3VtZXIAAAATAAAAAQAAAAE=",
        "AAAAAAAAAAAAAAAaY29uc3VtZV9taW50X2F1dGhvcml6YXRpb24AAAAAAAQAAAAAAAAACGNvbnN1bWVyAAAAEwAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAAAAAAdhY2NvdW50AAAAABMAAAAAAAAABmFtb3VudAAAAAAACwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAQAAAAAAAAAAAAAABVByb29mAAAAAAAAAwAAAAAAAAABYQAAAAAAA+4AAABgAAAAAAAAAAFiAAAAAAAD7gAAAMAAAAAAAAAAAWMAAAAAAAPuAAAAYA==",
        "AAAAAQAAAAAAAAAAAAAABlBvbGljeQAAAAAACQAAAAAAAAAPYWxsb3dlZF9jb3VudHJ5AAAAAAQAAAAAAAAACmNpcmN1aXRfaWQAAAAAA+4AAAAgAAAAAAAAAA9jaXJjdWl0X3ZlcnNpb24AAAAABAAAAAAAAAAJaXNzdWVyX2lkAAAAAAAABAAAAAAAAAAMa3ljX3JlcXVpcmVkAAAAAQAAAAAAAAAHbWluX2FnZQAAAAAEAAAAAAAAABFtaW5faW52ZXN0b3JfdHlwZQAAAAAAAAQAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAAAAAAEnNhbmN0aW9uc19yZXF1aXJlZAAAAAAAAQ==",
        "AAAAAQAAAAAAAAAAAAAAD1ZlcmlmaWNhdGlvbktleQAAAAAFAAAAAAAAAAVhbHBoYQAAAAAAA+4AAABgAAAAAAAAAARiZXRhAAAD7gAAAMAAAAAAAAAABWRlbHRhAAAAAAAD7gAAAMAAAAAAAAAABWdhbW1hAAAAAAAD7gAAAMAAAAAAAAAAAmljAAAAAAPqAAAD7gAAAGA=",
      ]),
      options,
    );
  }
  public readonly fromJSON = {
    init: this.txFromJSON<Result<void>>,
    pause: this.txFromJSON<Result<void>>,
    attest: this.txFromJSON<Result<void>>,
    paused: this.txFromJSON<boolean>,
    unpause: this.txFromJSON<Result<void>>,
    rwa_token: this.txFromJSON<Option<string>>,
    rwa_recipient: this.txFromJSON<Option<string>>,
    set_rwa_token: this.txFromJSON<Result<void>>,
    attest_for_mint: this.txFromJSON<Result<void>>,
    recovery_target: this.txFromJSON<Option<string>>,
    verify_identity: this.txFromJSON<Result<void>>,
    set_rwa_recipient: this.txFromJSON<Result<void>>,
    attestation_expiry: this.txFromJSON<Option<u64>>,
    mint_authorization: this.txFromJSON<Option<MintAuthorization>>,
    allow_mint_consumer: this.txFromJSON<Result<void>>,
    revoke_mint_consumer: this.txFromJSON<Result<void>>,
    is_mint_consumer_allowed: this.txFromJSON<boolean>,
    consume_mint_authorization: this.txFromJSON<Result<void>>,
  };
}
