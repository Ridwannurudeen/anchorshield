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
  8: {message:"PacketHashMismatch"},
  9: {message:"NullifierUsed"},
  10: {message:"InvalidProof"},
  11: {message:"MalformedVerifyingKey"},
  12: {message:"BadAmount"},
  13: {message:"InsufficientEscrow"}
}


export interface Proof {
  a: Buffer;
  b: Buffer;
  c: Buffer;
}


export interface Policy {
  allowed_country: u32;
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
  init: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a escrow transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  escrow: ({asset_id}: {asset_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a balance transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  balance: ({asset_id, recipient}: {asset_id: u32, recipient: u128}, options?: MethodOptions) => Promise<AssembledTransaction<i128>>

  /**
   * Construct and simulate a set_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_root: ({issuer_id, root}: {issuer_id: u32, root: u256}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a set_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_policy: ({policy}: {policy: Policy}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a verify_and_pay transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  verify_and_pay: ({vk, proof, pub_signals, policy_id, asset_id, amount, recipient, action_id, packet_hash, epoch}: {vk: VerificationKey, proof: Proof, pub_signals: Array<u256>, policy_id: u32, asset_id: u32, amount: i128, recipient: u128, action_id: u128, packet_hash: u256, epoch: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a is_nullifier_used transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  is_nullifier_used: ({nullifier}: {nullifier: u256}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

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
      new ContractSpec([ "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAADQAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAABAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAgAAAAAAAAANTWlzc2luZ1BvbGljeQAAAAAAAAMAAAAAAAAAC01pc3NpbmdSb290AAAAAAQAAAAAAAAAFk1hbGZvcm1lZFB1YmxpY1NpZ25hbHMAAAAAAAUAAAAAAAAAE1B1YmxpY0lucHV0TWlzbWF0Y2gAAAAABgAAAAAAAAAMUm9vdE1pc21hdGNoAAAABwAAAAAAAAASUGFja2V0SGFzaE1pc21hdGNoAAAAAAAIAAAAAAAAAA1OdWxsaWZpZXJVc2VkAAAAAAAACQAAAAAAAAAMSW52YWxpZFByb29mAAAACgAAAAAAAAAVTWFsZm9ybWVkVmVyaWZ5aW5nS2V5AAAAAAAACwAAAAAAAAAJQmFkQW1vdW50AAAAAAAADAAAAAAAAAASSW5zdWZmaWNpZW50RXNjcm93AAAAAAAN",
        "AAAAAQAAAAAAAAAAAAAABVByb29mAAAAAAAAAwAAAAAAAAABYQAAAAAAA+4AAABgAAAAAAAAAAFiAAAAAAAD7gAAAMAAAAAAAAAAAWMAAAAAAAPuAAAAYA==",
        "AAAAAQAAAAAAAAAAAAAABlBvbGljeQAAAAAABwAAAAAAAAAPYWxsb3dlZF9jb3VudHJ5AAAAAAQAAAAAAAAACWlzc3Vlcl9pZAAAAAAAAAQAAAAAAAAADGt5Y19yZXF1aXJlZAAAAAEAAAAAAAAAB21pbl9hZ2UAAAAABAAAAAAAAAARbWluX2ludmVzdG9yX3R5cGUAAAAAAAAEAAAAAAAAAAlwb2xpY3lfaWQAAAAAAAAEAAAAAAAAABJzYW5jdGlvbnNfcmVxdWlyZWQAAAAAAAE=",
        "AAAAAAAAAAAAAAAEZnVuZAAAAAIAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAEaW5pdAAAAAEAAAAAAAAABWFkbWluAAAAAAAAEwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAAGZXNjcm93AAAAAAABAAAAAAAAAAhhc3NldF9pZAAAAAQAAAABAAAACw==",
        "AAAAAAAAAAAAAAAHYmFsYW5jZQAAAAACAAAAAAAAAAhhc3NldF9pZAAAAAQAAAAAAAAACXJlY2lwaWVudAAAAAAAAAoAAAABAAAACw==",
        "AAAAAAAAAAAAAAAIc2V0X3Jvb3QAAAACAAAAAAAAAAlpc3N1ZXJfaWQAAAAAAAAEAAAAAAAAAARyb290AAAADAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAAKc2V0X3BvbGljeQAAAAAAAQAAAAAAAAAGcG9saWN5AAAAAAfQAAAABlBvbGljeQAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAQAAAAAAAAAAAAAAD1ZlcmlmaWNhdGlvbktleQAAAAAFAAAAAAAAAAVhbHBoYQAAAAAAA+4AAABgAAAAAAAAAARiZXRhAAAD7gAAAMAAAAAAAAAABWRlbHRhAAAAAAAD7gAAAMAAAAAAAAAABWdhbW1hAAAAAAAD7gAAAMAAAAAAAAAAAmljAAAAAAPqAAAD7gAAAGA=",
        "AAAABQAAAAAAAAAAAAAAD1BheW1lbnRBcHByb3ZlZAAAAAACAAAAB3BheW1lbnQAAAAACGFwcHJvdmVkAAAABgAAAAAAAAAJcG9saWN5X2lkAAAAAAAABAAAAAAAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAAAAAABmFtb3VudAAAAAAACwAAAAAAAAAAAAAACXJlY2lwaWVudAAAAAAAAAoAAAAAAAAAAAAAAAlhY3Rpb25faWQAAAAAAAAKAAAAAAAAAAAAAAAJbnVsbGlmaWVyAAAAAAAD7gAAACAAAAAAAAAAAg==",
        "AAAAAAAAAAAAAAAOdmVyaWZ5X2FuZF9wYXkAAAAAAAoAAAAAAAAAAnZrAAAAAAfQAAAAD1ZlcmlmaWNhdGlvbktleQAAAAAAAAAABXByb29mAAAAAAAH0AAAAAVQcm9vZgAAAAAAAAAAAAALcHViX3NpZ25hbHMAAAAD6gAAAAwAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAAAAAACGFzc2V0X2lkAAAABAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAAAAAAlyZWNpcGllbnQAAAAAAAAKAAAAAAAAAAlhY3Rpb25faWQAAAAAAAAKAAAAAAAAAAtwYWNrZXRfaGFzaAAAAAAMAAAAAAAAAAVlcG9jaAAAAAAAAAQAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAARaXNfbnVsbGlmaWVyX3VzZWQAAAAAAAABAAAAAAAAAAludWxsaWZpZXIAAAAAAAAMAAAAAQAAAAE=" ]),
      options
    )
  }
  public readonly fromJSON = {
    fund: this.txFromJSON<Result<void>>,
        init: this.txFromJSON<Result<void>>,
        escrow: this.txFromJSON<i128>,
        balance: this.txFromJSON<i128>,
        set_root: this.txFromJSON<Result<void>>,
        set_policy: this.txFromJSON<Result<void>>,
        verify_and_pay: this.txFromJSON<Result<void>>,
        is_nullifier_used: this.txFromJSON<boolean>
  }
}