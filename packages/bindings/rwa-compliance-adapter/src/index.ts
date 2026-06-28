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
  3: {message:"NotAuthorized"},
  4: {message:"TokenAlreadyBound"},
  5: {message:"TokenNotBound"},
  6: {message:"BadAmount"}
}


export type TransferKind = {tag: "Standard", values: void} | {tag: "Delegated", values: readonly [string]} | {tag: "Forced", values: void};



export interface AccountSnapshot {
  address: string;
  balance: i128;
  frozen: i128;
}

export interface Client {
  /**
   * Construct and simulate a init transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  init: ({admin, identity_verifier}: {admin: string, identity_verifier: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a created transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  created: ({to, amount, token}: {to: AccountSnapshot, amount: i128, token: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a destroyed transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  destroyed: ({from, amount, token}: {from: AccountSnapshot, amount: i128, token: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a bind_token transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  bind_token: ({token, operator}: {token: string, operator: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a transferred transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  transferred: ({from, to, amount, kind, token}: {from: AccountSnapshot, to: AccountSnapshot, amount: i128, kind: TransferKind, token: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a unbind_token transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  unbind_token: ({token, operator}: {token: string, operator: string}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a is_token_bound transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  is_token_bound: ({token}: {token: string}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a identity_verifier transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  identity_verifier: (options?: MethodOptions) => Promise<AssembledTransaction<Result<string>>>

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
      new ContractSpec([ "AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAABgAAAAAAAAASQWxyZWFkeUluaXRpYWxpemVkAAAAAAABAAAAAAAAAA5Ob3RJbml0aWFsaXplZAAAAAAAAgAAAAAAAAANTm90QXV0aG9yaXplZAAAAAAAAAMAAAAAAAAAEVRva2VuQWxyZWFkeUJvdW5kAAAAAAAABAAAAAAAAAANVG9rZW5Ob3RCb3VuZAAAAAAAAAUAAAAAAAAACUJhZEFtb3VudAAAAAAAAAY=",
        "AAAABQAAAAAAAAAAAAAAClRva2VuQm91bmQAAAAAAAIAAAAOcndhX2NvbXBsaWFuY2UAAAAAAAt0b2tlbl9ib3VuZAAAAAABAAAAAAAAAAV0b2tlbgAAAAAAABMAAAAAAAAAAg==",
        "AAAAAgAAAAAAAAAAAAAADFRyYW5zZmVyS2luZAAAAAMAAAAAAAAAAAAAAAhTdGFuZGFyZAAAAAEAAAAAAAAACURlbGVnYXRlZAAAAAAAAAEAAAATAAAAAAAAAAAAAAAGRm9yY2VkAAA=",
        "AAAABQAAAAAAAAAAAAAADFRva2VuVW5ib3VuZAAAAAIAAAAOcndhX2NvbXBsaWFuY2UAAAAAAA10b2tlbl91bmJvdW5kAAAAAAAAAQAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAAAAAAI=",
        "AAAAAQAAAAAAAAAAAAAAD0FjY291bnRTbmFwc2hvdAAAAAADAAAAAAAAAAdhZGRyZXNzAAAAABMAAAAAAAAAB2JhbGFuY2UAAAAACwAAAAAAAAAGZnJvemVuAAAAAAAL",
        "AAAAAAAAAAAAAAAEaW5pdAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAARaWRlbnRpdHlfdmVyaWZpZXIAAAAAAAATAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAHY3JlYXRlZAAAAAADAAAAAAAAAAJ0bwAAAAAH0AAAAA9BY2NvdW50U25hcHNob3QAAAAAAAAAAAZhbW91bnQAAAAAAAsAAAAAAAAABXRva2VuAAAAAAAAEwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAAJZGVzdHJveWVkAAAAAAAAAwAAAAAAAAAEZnJvbQAAB9AAAAAPQWNjb3VudFNuYXBzaG90AAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAAAAAAV0b2tlbgAAAAAAABMAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAAKYmluZF90b2tlbgAAAAAAAgAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAAAAAAhvcGVyYXRvcgAAABMAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAALdHJhbnNmZXJyZWQAAAAABQAAAAAAAAAEZnJvbQAAB9AAAAAPQWNjb3VudFNuYXBzaG90AAAAAAAAAAACdG8AAAAAB9AAAAAPQWNjb3VudFNuYXBzaG90AAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAAAAAARraW5kAAAH0AAAAAxUcmFuc2ZlcktpbmQAAAAAAAAABXRva2VuAAAAAAAAEwAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAAMdW5iaW5kX3Rva2VuAAAAAgAAAAAAAAAFdG9rZW4AAAAAAAATAAAAAAAAAAhvcGVyYXRvcgAAABMAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAAOaXNfdG9rZW5fYm91bmQAAAAAAAEAAAAAAAAABXRva2VuAAAAAAAAEwAAAAEAAAAB",
        "AAAAAAAAAAAAAAARaWRlbnRpdHlfdmVyaWZpZXIAAAAAAAAAAAAAAQAAA+kAAAATAAAAAw==" ]),
      options
    )
  }
  public readonly fromJSON = {
    init: this.txFromJSON<Result<void>>,
        created: this.txFromJSON<Result<void>>,
        destroyed: this.txFromJSON<Result<void>>,
        bind_token: this.txFromJSON<Result<void>>,
        transferred: this.txFromJSON<Result<void>>,
        unbind_token: this.txFromJSON<Result<void>>,
        is_token_bound: this.txFromJSON<boolean>,
        identity_verifier: this.txFromJSON<Result<string>>
  }
}