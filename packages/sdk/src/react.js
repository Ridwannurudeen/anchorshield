const React = require("react");
const core = require("./index");

function browserFreighter() {
  return typeof window !== "undefined" ? window.freighterApi : null;
}

function responseError(value) {
  const error = value?.error;
  if (!error) return null;
  if (typeof error === "string") return error;
  return error.message || JSON.stringify(error);
}

async function requestWalletAccess(freighterApi) {
  if (!freighterApi?.requestAccess) {
    throw new Error("Freighter requestAccess API is required");
  }
  if (freighterApi.isConnected) {
    const connected = await freighterApi.isConnected();
    const error = responseError(connected);
    if (error) throw new Error(error);
  }
  const access = await freighterApi.requestAccess();
  const error = responseError(access);
  if (error) throw new Error(error);
  if (!access.address) {
    throw new Error("Freighter did not return an address");
  }
  return access.address;
}

function useAnchorShield(options = {}) {
  const [address, setAddress] = React.useState(options.sourceAddress || "");
  const [status, setStatus] = React.useState("idle");
  const [error, setError] = React.useState(null);
  const [result, setResult] = React.useState(null);

  const connect = React.useCallback(async () => {
    setStatus("connecting");
    setError(null);
    try {
      const nextAddress = await requestWalletAccess(
        options.freighterApi || browserFreighter(),
      );
      setAddress(nextAddress);
      setStatus("connected");
      return nextAddress;
    } catch (e) {
      setStatus("error");
      setError(e);
      throw e;
    }
  }, [options.freighterApi]);

  const submitPaymentProof = React.useCallback(
    async (request) => {
      setStatus("submitting");
      setError(null);
      try {
        const sourceAddress =
          request.sourceAddress || address || (await connect());
        const submitted = await core.submitPaymentProof({
          stellarSdk: options.stellarSdk,
          freighterApi: options.freighterApi || browserFreighter(),
          rpcUrl: request.rpcUrl || options.rpcUrl,
          networkPassphrase:
            request.networkPassphrase || options.networkPassphrase,
          contractId: request.contractId || options.contractId,
          sourceAddress,
          proof: request.proof,
          publicSignals: request.publicSignals,
          action: request.action,
          specEntries: request.specEntries || options.specEntries,
          fee: request.fee || options.fee,
          timeout: request.timeout || options.timeout,
          pollIntervalMs: request.pollIntervalMs || options.pollIntervalMs,
          pollAttempts: request.pollAttempts || options.pollAttempts,
        });
        setAddress(sourceAddress);
        setResult(submitted);
        setStatus(submitted.status === "PENDING" ? "pending" : "submitted");
        return submitted;
      } catch (e) {
        setStatus("error");
        setError(e);
        throw e;
      }
    },
    [
      address,
      connect,
      options.contractId,
      options.fee,
      options.freighterApi,
      options.networkPassphrase,
      options.pollAttempts,
      options.pollIntervalMs,
      options.rpcUrl,
      options.specEntries,
      options.stellarSdk,
      options.timeout,
    ],
  );

  return React.useMemo(
    () => ({
      address,
      connect,
      error,
      result,
      status,
      submitPaymentProof,
    }),
    [address, connect, error, result, status, submitPaymentProof],
  );
}

function AnchorShieldGate({
  action,
  buttonProps = {},
  children,
  disabled = false,
  onError,
  onSuccess,
  pendingLabel = "Submitting proof",
  proof,
  publicSignals,
  specEntries,
  ...options
}) {
  const gate = useAnchorShield(options);
  const handleClick = React.useCallback(async () => {
    try {
      const submitted = await gate.submitPaymentProof({
        action,
        proof,
        publicSignals,
        specEntries,
      });
      if (onSuccess) onSuccess(submitted);
    } catch (e) {
      if (onError) onError(e);
    }
  }, [action, gate, onError, onSuccess, proof, publicSignals, specEntries]);

  const label =
    gate.status === "submitting"
      ? pendingLabel
      : typeof children === "function"
        ? children(gate)
        : children || "Submit AnchorShield proof";

  return React.createElement(
    "button",
    {
      type: "button",
      ...buttonProps,
      disabled:
        disabled || gate.status === "submitting" || buttonProps.disabled,
      onClick: handleClick,
    },
    label,
  );
}

module.exports = {
  AnchorShieldGate,
  requestWalletAccess,
  useAnchorShield,
};
