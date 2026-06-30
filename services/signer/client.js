const DEFAULT_SIGNER_PORT = 3099;

async function readJsonResponse(response) {
  if (typeof response.json === "function") {
    return response.json();
  }
  if (typeof response.text === "function") {
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }
  return null;
}

function rootPublishError(message, cause) {
  const error = new Error(message);
  error.code = "ROOT_PUBLISH_FAILED";
  if (cause) {
    error.cause = cause;
  }
  return error;
}

async function publishCredentialRootViaSigner({
  issuerId,
  fetchImpl = globalThis.fetch,
  signerPort = process.env.SIGNER_PORT || DEFAULT_SIGNER_PORT,
  signerToken = process.env.SIGNER_TOKEN,
} = {}) {
  if (!signerToken) {
    throw rootPublishError("signer token is not configured");
  }
  if (typeof fetchImpl !== "function") {
    throw rootPublishError("fetch is not available for signer client");
  }

  let response;
  try {
    response = await fetchImpl(
      `http://127.0.0.1:${Number(signerPort)}/publish-credential-root`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${signerToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ issuerId }),
      },
    );
  } catch (error) {
    throw rootPublishError("credential root signer request failed", error);
  }

  const body = await readJsonResponse(response);
  if (!response.ok) {
    throw rootPublishError(
      body?.error || `credential root signer returned ${response.status}`,
    );
  }
  return body;
}

module.exports = {
  DEFAULT_SIGNER_PORT,
  publishCredentialRootViaSigner,
};
