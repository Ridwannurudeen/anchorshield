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
  1: {message:"AlreadyInitialized"},
  2: {message:"NotInitialized"},
  3: {message:"MissingPolicy"},
  4: {message:"MissingRoot"},
  5: {message:"MalformedPublicSignals"},
  6: {message:"PublicInputMismatch"},
  7: {message:"RootMismatch"},
  8: {message:"TermsHashMismatch"},
  9: {message:"NullifierUsed"},
  10: {message:"InvalidProof"},
  11: {message:"MalformedVerifyingKey"},
  12: {message:"BadAmount"},
  13: {message:"InsufficientInventory"},
  14: {message:"MissingSanctionsRoot"},
  15: {message:"MissingRevocationRoot"},
  16: {message:"SanctionsRootMismatch"},
  17: {message:"RevocationRootMismatch"},
  18: {message:"Paused"},
  19: {message:"CircuitMismatch"}
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
   * Construct and simulate a fund transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  fund: ({asset_id, amount}: {asset_id: u32, amount: i128}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a init transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  init: ({admin, verifier, issuer_registry, policy_registry, nullifier_registry}: {admin: string, verifier: string, issuer_registry: string, policy_registry: string, nullifier_registry: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a pause transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  pause: (options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a paused transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  paused: (options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a holding transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  holding: ({asset_id, recipient}: {asset_id: u32, recipient: u128}, options?: MethodOptions) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a unpause transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  unpause: (options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a inventory transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  inventory: ({asset_id}: {asset_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a verify_and_transfer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  verify_and_transfer: ({proof, pub_signals, policy_id, asset_id, amount, recipient, action_id, terms_hash, epoch}: {proof: Proof, pub_signals: Array<u256>, policy_id: u32, asset_id: u32, amount: i128, recipient: u128, action_id: u128, terms_hash: u256, epoch: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

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
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(null, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAAAAAAAAAAAEZnVuZAAAAAIAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAEaW5pdAAAAAUAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAIdmVyaWZpZXIAAAATAAAAAAAAAA9pc3N1ZXJfcmVnaXN0cnkAAAAAEwAAAAAAAAAPcG9saWN5X3JlZ2lzdHJ5AAAAABMAAAAAAAAAEm51bGxpZmllcl9yZWdpc3RyeQAAAAAAEwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAEwAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAABAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAgAAAAAAAAANTWlzc2luZ1BvbGljeQAAAAAAAAMAAAAAAAAAC01pc3NpbmdSb290AAAAAAQAAAAAAAAAFk1hbGZvcm1lZFB1YmxpY1NpZ25hbHMAAAAAAAUAAAAAAAAAE1B1YmxpY0lucHV0TWlzbWF0Y2gAAAAABgAAAAAAAAAMUm9vdE1pc21hdGNoAAAABwAAAAAAAAARVGVybXNIYXNoTWlzbWF0Y2gAAAAAAAAIAAAAAAAAAA1OdWxsaWZpZXJVc2VkAAAAAAAACQAAAAAAAAAMSW52YWxpZFByb29mAAAACgAAAAAAAAAVTWFsZm9ybWVkVmVyaWZ5aW5nS2V5AAAAAAAACwAAAAAAAAAJQmFkQW1vdW50AAAAAAAADAAAAAAAAAAVSW5zdWZmaWNpZW50SW52ZW50b3J5AAAAAAAADQAAAAAAAAAUTWlzc2luZ1NhbmN0aW9uc1Jvb3QAAAAOAAAAAAAAABVNaXNzaW5nUmV2b2NhdGlvblJvb3QAAAAAAAAPAAAAAAAAABVTYW5jdGlvbnNSb290TWlzbWF0Y2gAAAAAAAAQAAAAAAAAABZSZXZvY2F0aW9uUm9vdE1pc21hdGNoAAAAAAARAAAAAAAAAAZQYXVzZWQAAAAAABIAAAAAAAAAD0NpcmN1aXRNaXNtYXRjaAAAAAAT",
        "AAAAAAAAAAAAAAAFcGF1c2UAAAAAAAAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAGcGF1c2VkAAAAAAAAAAAAAQAAAAE=",
        "AAAABQAAAAAAAAAAAAAABlBhdXNlZAAAAAAAAgAAAANyd2EAAAAABnBhdXNlZAAAAAAAAAAAAAI=",
        "AAAAAAAAAAAAAAAHaG9sZGluZwAAAAACAAAAAAAAAAhhc3NldF9pZAAAAAQAAAAAAAAACXJlY2lwaWVudAAAAAAAAAoAAAABAAAACw==",
        "AAAAAAAAAAAAAAAHdW5wYXVzZQAAAAAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAABQAAAAAAAAAAAAAACFVucGF1c2VkAAAAAgAAAANyd2EAAAAACHVucGF1c2VkAAAAAAAAAAI=",
        "AAAAAAAAAAAAAAAJaW52ZW50b3J5AAAAAAAAAQAAAAAAAAAIYXNzZXRfaWQAAAAEAAAAAQAAAAs=",
        "AAAAAAAAAAAAAAATdmVyaWZ5X2FuZF90cmFuc2ZlcgAAAAAJAAAAAAAAAAVwcm9vZgAAAAAAB9AAAAAFUHJvb2YAAAAAAAAAAAAAC3B1Yl9zaWduYWxzAAAAA+oAAAAMAAAAAAAAAAlwb2xpY3lfaWQAAAAAAAAEAAAAAAAAAAhhc3NldF9pZAAAAAQAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAJcmVjaXBpZW50AAAAAAAACgAAAAAAAAAJYWN0aW9uX2lkAAAAAAAACgAAAAAAAAAKdGVybXNfaGFzaAAAAAAADAAAAAAAAAAFZXBvY2gAAAAAAAAEAAAAAQAAA+kAAAACAAAAAw==",
        "AAAABQAAAAAAAAAAAAAAE1J3YVRyYW5zZmVyQXBwcm92ZWQAAAAAAgAAAANyd2EAAAAACGFwcHJvdmVkAAAACAAAAAAAAAAJcG9saWN5X2lkAAAAAAAABAAAAAAAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAAAAAACXJlY2lwaWVudAAAAAAAAAoAAAAAAAAAAAAAAAlhY3Rpb25faWQAAAAAAAAKAAAAAAAAAAAAAAAJbnVsbGlmaWVyAAAAAAAD7gAAACAAAAAAAAAAAAAAAAp0ZXJtc19oYXNoAAAAAAPuAAAAIAAAAAAAAAAAAAAADmFjdGlvbl9iaW5kaW5nAAAAAAPuAAAAIAAAAAAAAAAC",
        "AAAAAQAAAAAAAAAAAAAABVByb29mAAAAAAAAAwAAAAAAAAABYQAAAAAAA+4AAABgAAAAAAAAAAFiAAAAAAAD7gAAAMAAAAAAAAAAAWMAAAAAAAPuAAAAYA==",
        "AAAAAQAAAAAAAAAAAAAABlBvbGljeQAAAAAACQAAAAAAAAAPYWxsb3dlZF9jb3VudHJ5AAAAAAQAAAAAAAAACmNpcmN1aXRfaWQAAAAAA+4AAAAgAAAAAAAAAA9jaXJjdWl0X3ZlcnNpb24AAAAABAAAAAAAAAAJaXNzdWVyX2lkAAAAAAAABAAAAAAAAAAMa3ljX3JlcXVpcmVkAAAAAQAAAAAAAAAHbWluX2FnZQAAAAAEAAAAAAAAABFtaW5faW52ZXN0b3JfdHlwZQAAAAAAAAQAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAAAAAAEnNhbmN0aW9uc19yZXF1aXJlZAAAAAAAAQ==",
        "AAAAAQAAAAAAAAAAAAAAD1ZlcmlmaWNhdGlvbktleQAAAAAFAAAAAAAAAAVhbHBoYQAAAAAAA+4AAABgAAAAAAAAAARiZXRhAAAD7gAAAMAAAAAAAAAABWRlbHRhAAAAAAAD7gAAAMAAAAAAAAAABWdhbW1hAAAAAAAD7gAAAMAAAAAAAAAAAmljAAAAAAPqAAAD7gAAAGA=" ]),
      options
    )
  }
  public readonly fromJSON = {
    fund: this.txFromJSON<Result<void>>,
        init: this.txFromJSON<Result<void>>,
        pause: this.txFromJSON<Result<void>>,
        paused: this.txFromJSON<boolean>,
        holding: this.txFromJSON<i128>,
        unpause: this.txFromJSON<Result<void>>,
        inventory: this.txFromJSON<i128>,
        verify_and_transfer: this.txFromJSON<Result<void>>
  }
}