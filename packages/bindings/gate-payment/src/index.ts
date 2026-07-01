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
  8: { message: "PacketHashMismatch" },
  9: { message: "NullifierUsed" },
  10: { message: "InvalidProof" },
  11: { message: "MalformedVerifyingKey" },
  12: { message: "BadAmount" },
  13: { message: "MissingToken" },
  14: { message: "MissingRecipient" },
  15: { message: "AlreadySet" },
  16: { message: "MissingSanctionsRoot" },
  17: { message: "MissingRevocationRoot" },
  18: { message: "SanctionsRootMismatch" },
  19: { message: "RevocationRootMismatch" },
  20: { message: "Paused" },
  21: { message: "CircuitMismatch" },
  22: { message: "AnonymitySetTooSmall" },
  23: { message: "NotPauser" },
  24: { message: "NoPendingAdmin" },
};

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
   * Construct and simulate a token transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  token: (
    { asset_id }: { asset_id: u32 },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<string>>>;

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
   * Construct and simulate a recipient transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  recipient: (
    { recipient_id }: { recipient_id: u128 },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Option<string>>>;

  /**
   * Construct and simulate a set_token transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Admin-only. Maps an `asset_id` circuit signal to a Stellar Asset Contract.
   */
  set_token: (
    { asset_id, token }: { asset_id: u32; token: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a set_recipient transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Admin-only. Registers the real payee address for a `recipient_id` signal.
   */
  set_recipient: (
    { recipient_id, recipient }: { recipient_id: u128; recipient: string },
    options?: MethodOptions,
  ) => Promise<AssembledTransaction<Result<void>>>;

  /**
   * Construct and simulate a verify_and_pay transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  verify_and_pay: (
    {
      proof,
      pub_signals,
      policy_id,
      asset_id,
      amount,
      recipient_id,
      action_id,
      packet_hash,
      epoch,
    }: {
      proof: Proof;
      pub_signals: Array<u256>;
      policy_id: u32;
      asset_id: u32;
      amount: i128;
      recipient_id: u128;
      action_id: u128;
      packet_hash: u256;
      epoch: u32;
    },
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
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAFQAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAABAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAgAAAAAAAAANTWlzc2luZ1BvbGljeQAAAAAAAAMAAAAAAAAAC01pc3NpbmdSb290AAAAAAQAAAAAAAAAFk1hbGZvcm1lZFB1YmxpY1NpZ25hbHMAAAAAAAUAAAAAAAAAE1B1YmxpY0lucHV0TWlzbWF0Y2gAAAAABgAAAAAAAAAMUm9vdE1pc21hdGNoAAAABwAAAAAAAAASUGFja2V0SGFzaE1pc21hdGNoAAAAAAAIAAAAAAAAAA1OdWxsaWZpZXJVc2VkAAAAAAAACQAAAAAAAAAMSW52YWxpZFByb29mAAAACgAAAAAAAAAVTWFsZm9ybWVkVmVyaWZ5aW5nS2V5AAAAAAAACwAAAAAAAAAJQmFkQW1vdW50AAAAAAAADAAAAAAAAAAMTWlzc2luZ1Rva2VuAAAADQAAAAAAAAAQTWlzc2luZ1JlY2lwaWVudAAAAA4AAAAAAAAACkFscmVhZHlTZXQAAAAAAA8AAAAAAAAAFE1pc3NpbmdTYW5jdGlvbnNSb290AAAAEAAAAAAAAAAVTWlzc2luZ1Jldm9jYXRpb25Sb290AAAAAAAAEQAAAAAAAAAVU2FuY3Rpb25zUm9vdE1pc21hdGNoAAAAAAAAEgAAAAAAAAAWUmV2b2NhdGlvblJvb3RNaXNtYXRjaAAAAAAAEwAAAAAAAAAGUGF1c2VkAAAAAAAUAAAAAAAAAA9DaXJjdWl0TWlzbWF0Y2gAAAAAFQ==",
        "AAAABQAAAAAAAAAAAAAABlBhdXNlZAAAAAAAAgAAAAdwYXltZW50AAAAAAZwYXVzZWQAAAAAAAAAAAAC",
        "AAAAAAAAAAAAAAAEaW5pdAAAAAUAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAIdmVyaWZpZXIAAAATAAAAAAAAAA9pc3N1ZXJfcmVnaXN0cnkAAAAAEwAAAAAAAAAPcG9saWN5X3JlZ2lzdHJ5AAAAABMAAAAAAAAAEm51bGxpZmllcl9yZWdpc3RyeQAAAAAAEwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAABQAAAAAAAAAAAAAACFVucGF1c2VkAAAAAgAAAAdwYXltZW50AAAAAAh1bnBhdXNlZAAAAAAAAAAC",
        "AAAAAAAAAAAAAAAFcGF1c2UAAAAAAAAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAFdG9rZW4AAAAAAAABAAAAAAAAAAhhc3NldF9pZAAAAAQAAAABAAAD6AAAABM=",
        "AAAAAAAAAAAAAAAGcGF1c2VkAAAAAAAAAAAAAQAAAAE=",
        "AAAAAAAAAAAAAAAHdW5wYXVzZQAAAAAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAABQAAAAAAAAAAAAAAC1Rva2VuTWFwcGVkAAAAAAIAAAAHcGF5bWVudAAAAAAMdG9rZW5fbWFwcGVkAAAAAgAAAAAAAAAIYXNzZXRfaWQAAAAEAAAAAAAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAAAAAAI=",
        "AAAAAAAAAAAAAAAJcmVjaXBpZW50AAAAAAAAAQAAAAAAAAAMcmVjaXBpZW50X2lkAAAACgAAAAEAAAPoAAAAEw==",
        "AAAAAAAAAEpBZG1pbi1vbmx5LiBNYXBzIGFuIGBhc3NldF9pZGAgY2lyY3VpdCBzaWduYWwgdG8gYSBTdGVsbGFyIEFzc2V0IENvbnRyYWN0LgAAAAAACXNldF90b2tlbgAAAAAAAAIAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAQAAA+kAAAACAAAAAw==",
        "AAAABQAAAAAAAAAAAAAAD1BheW1lbnRBcHByb3ZlZAAAAAACAAAAB3BheW1lbnQAAAAACGFwcHJvdmVkAAAACAAAAAAAAAAJcG9saWN5X2lkAAAAAAAABAAAAAAAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAAAAAACXJlY2lwaWVudAAAAAAAABMAAAAAAAAAAAAAAAlhY3Rpb25faWQAAAAAAAAKAAAAAAAAAAAAAAAJbnVsbGlmaWVyAAAAAAAD7gAAACAAAAAAAAAAAAAAAAtwYWNrZXRfaGFzaAAAAAPuAAAAIAAAAAAAAAAAAAAADmFjdGlvbl9iaW5kaW5nAAAAAAPuAAAAIAAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAD1JlY2lwaWVudE1hcHBlZAAAAAACAAAAB3BheW1lbnQAAAAAEHJlY2lwaWVudF9tYXBwZWQAAAACAAAAAAAAAAxyZWNpcGllbnRfaWQAAAAKAAAAAAAAAAAAAAAJcmVjaXBpZW50AAAAAAAAEwAAAAAAAAAC",
        "AAAAAAAAAElBZG1pbi1vbmx5LiBSZWdpc3RlcnMgdGhlIHJlYWwgcGF5ZWUgYWRkcmVzcyBmb3IgYSBgcmVjaXBpZW50X2lkYCBzaWduYWwuAAAAAAAADXNldF9yZWNpcGllbnQAAAAAAAACAAAAAAAAAAxyZWNpcGllbnRfaWQAAAAKAAAAAAAAAAlyZWNpcGllbnQAAAAAAAATAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAOdmVyaWZ5X2FuZF9wYXkAAAAAAAkAAAAAAAAABXByb29mAAAAAAAH0AAAAAVQcm9vZgAAAAAAAAAAAAALcHViX3NpZ25hbHMAAAAD6gAAAAwAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAAAAAAxyZWNpcGllbnRfaWQAAAAKAAAAAAAAAAlhY3Rpb25faWQAAAAAAAAKAAAAAAAAAAtwYWNrZXRfaGFzaAAAAAAMAAAAAAAAAAVlcG9jaAAAAAAAAAQAAAABAAAD6QAAAAIAAAAD",
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
    token: this.txFromJSON<Option<string>>,
    paused: this.txFromJSON<boolean>,
    unpause: this.txFromJSON<Result<void>>,
    recipient: this.txFromJSON<Option<string>>,
    set_token: this.txFromJSON<Result<void>>,
    set_recipient: this.txFromJSON<Result<void>>,
    verify_and_pay: this.txFromJSON<Result<void>>,
  };
}
