"use client";
import { useState } from "react";
import { useTurnkey, AuthState, OtpType } from "@turnkey/react-wallet-kit";

// Helper to convert ArrayBuffer to hex string
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Compress an uncompressed P-256 public key (04 || X || Y) into SEC1 compressed
// form (02/03 || X). Turnkey's stamp verifier and credential lookup both
// require the compressed form; registering uncompressed keys leaves them
// unusable for API auth.
function compressP256PublicKey(uncompressedHex: string): string {
  if (uncompressedHex.length !== 130 || !uncompressedHex.startsWith("04")) {
    throw new Error("Expected uncompressed P-256 public key (04 || X || Y, 130 hex chars)");
  }
  const x = uncompressedHex.slice(2, 66);
  const y = uncompressedHex.slice(66);
  const yIsOdd = parseInt(y.slice(-2), 16) % 2 === 1;
  return (yIsOdd ? "03" : "02") + x;
}

// Export CryptoKeyPair to hex strings. Public key is returned in compressed
// SEC1 form so it can be registered with Turnkey.
async function exportKeyPairToHex(keyPair: CryptoKeyPair): Promise<{ publicKey: string; privateKey: string }> {
  const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const publicKeyHex = compressP256PublicKey(bufferToHex(publicKeyRaw));

  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const privateKeyBytes = Uint8Array.from(
    atob(privateKeyJwk.d!.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );
  const privateKeyHex = bufferToHex(privateKeyBytes.buffer);

  return { publicKey: publicKeyHex, privateKey: privateKeyHex };
}

function formatTurnkeyError(error: unknown): string {
  if (!error || typeof error !== "object") return String(error);
  const err = error as { message?: string; code?: string; cause?: unknown };
  const parts: string[] = [];
  if (err.message) parts.push(err.message);
  if (err.code) parts.push(`code: ${err.code}`);
  if (err.cause) {
    const cause = err.cause as { message?: string };
    if (cause?.message) parts.push(`cause: ${cause.message}`);
  }
  return parts.join(" — ") || "Unknown error";
}

function AuthStatus() {
  const {
    authState,
    user,
    session,
    logout,
    deleteSubOrganization,
    initOtp,
    verifyOtp,
    loginWithOtp,
    createApiKeyPair,
    httpClient,
  } = useTurnkey();
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const [subOrgId, setSubOrgId] = useState("");
  const [email, setEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpId, setOtpId] = useState<string | null>(null);
  const [isSendingCode, setIsSendingCode] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  const handleSendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setIsSendingCode(true);
    try {
      const id = await initOtp({ otpType: OtpType.Email, contact: email });
      setOtpId(id);
    } catch (error) {
      console.error("Failed to send OTP:", error);
      setLoginError(formatTurnkeyError(error));
    } finally {
      setIsSendingCode(false);
    }
  };

  const handleVerifyAndLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otpId) return;
    setLoginError(null);
    setIsVerifying(true);
    try {
      // The verification token is bound to the public key supplied during
      // verifyOtp; loginWithOtp must sign with that same key, so mint one
      // here and reuse it across both calls.
      const sessionPublicKey = await createApiKeyPair();
      const { verificationToken } = await verifyOtp({
        otpId,
        otpCode,
        contact: email,
        otpType: OtpType.Email,
        publicKey: sessionPublicKey,
      });
      await loginWithOtp({
        verificationToken,
        organizationId: subOrgId,
        publicKey: sessionPublicKey,
      });
    } catch (error) {
      console.error("Failed to verify OTP:", error);
      setLoginError(formatTurnkeyError(error));
    } finally {
      setIsVerifying(false);
    }
  };

  const resetLoginForm = () => {
    setOtpId(null);
    setOtpCode("");
    setLoginError(null);
  };

  const handleDeleteUser = async () => {
    if (!confirm("Permanently delete this sub-organization and its user? This cannot be undone.")) {
      return;
    }
    setIsDeleting(true);
    try {
      await deleteSubOrganization({ deleteWithoutExport: true });
      await logout();
    } catch (error) {
      console.error("Failed to delete sub-organization:", error);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleGenerateKeyPair = async () => {
    if (!httpClient || !session?.userId) {
      console.error("HTTP client or user not initialized");
      return;
    }

    setIsGenerating(true);
    try {
      // Generate an extractable key pair
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      // Export keys to hex strings
      const hexKeys = await exportKeyPairToHex(keyPair);

      // Register the API key with Turnkey using createApiKeys
      await httpClient.createApiKeys({
        apiKeys: [
          {
            apiKeyName: `Generated Key ${Date.now()}`,
            publicKey: hexKeys.publicKey,
            curveType: "API_KEY_CURVE_P256",
          },
        ],
        userId: session.userId,
      });

      setPublicKey(hexKeys.publicKey);
      setPrivateKey(hexKeys.privateKey);
    } catch (error) {
      console.error("Failed to generate key pair:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center p-6 bg-neutral-50 dark:bg-neutral-950">
      <div className="w-full max-w-xl rounded-2xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900 shadow-sm p-8 space-y-6">
        {authState === AuthState.Authenticated ? (
          <>
            <header className="space-y-1">
              <h1 className="text-2xl font-semibold tracking-tight">
                {user?.userName}
              </h1>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                Organization ID:{" "}
                <code className="font-mono text-xs break-all">
                  {session?.organizationId}
                </code>
              </p>
            </header>

            <section className="space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                API keys
              </h2>
              <button
                onClick={handleGenerateKeyPair}
                disabled={isGenerating}
                className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium px-4 py-2.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
              >
                {isGenerating ? "Generating..." : "Generate API Key Pair"}
              </button>

              {publicKey && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
                    Public Key
                  </p>
                  <code className="block font-mono text-xs break-all p-3 rounded-md bg-neutral-100 dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700">
                    {publicKey}
                  </code>
                </div>
              )}

              {privateKey && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
                    Private Key
                  </p>
                  <code className="block font-mono text-xs break-all p-3 rounded-md bg-neutral-100 dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700">
                    {privateKey}
                  </code>
                </div>
              )}
            </section>

            <section className="space-y-3 pt-4 border-t border-neutral-200 dark:border-neutral-800">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                Session
              </h2>
              <div className="flex flex-col sm:flex-row gap-3">
                <button
                  onClick={() => logout()}
                  className="flex-1 rounded-lg border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-900 dark:text-neutral-100 font-medium px-4 py-2.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
                >
                  Log out
                </button>
                <button
                  onClick={handleDeleteUser}
                  disabled={isDeleting}
                  className="flex-1 rounded-lg bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white font-medium px-4 py-2.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
                >
                  {isDeleting ? "Deleting..." : "Delete suborg & user"}
                </button>
              </div>
            </section>
          </>
        ) : (
          <div className="space-y-5">
            <header className="space-y-1">
              <h1 className="text-2xl font-semibold tracking-tight">
                Suborg Keys
              </h1>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                Sign in to a specific sub-organization with email OTP.
              </p>
            </header>

            {!otpId ? (
              <form onSubmit={handleSendCode} className="space-y-4">
                <div className="space-y-1">
                  <label
                    htmlFor="subOrgId"
                    className="block text-xs font-medium text-neutral-700 dark:text-neutral-300"
                  >
                    Sub-organization ID
                  </label>
                  <input
                    id="subOrgId"
                    type="text"
                    required
                    value={subOrgId}
                    onChange={(e) => setSubOrgId(e.target.value.trim())}
                    placeholder="00000000-0000-0000-0000-000000000000"
                    className="w-full rounded-lg border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 px-3 py-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                <div className="space-y-1">
                  <label
                    htmlFor="email"
                    className="block text-xs font-medium text-neutral-700 dark:text-neutral-300"
                  >
                    Email
                  </label>
                  <input
                    id="email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value.trim())}
                    placeholder="you@example.com"
                    className="w-full rounded-lg border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {loginError && (
                  <p className="text-sm text-red-600 dark:text-red-400">{loginError}</p>
                )}

                <button
                  type="submit"
                  disabled={isSendingCode || !subOrgId || !email}
                  className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium px-4 py-2.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
                >
                  {isSendingCode ? "Sending code..." : "Send code"}
                </button>
              </form>
            ) : (
              <form onSubmit={handleVerifyAndLogin} className="space-y-4">
                <p className="text-sm text-neutral-600 dark:text-neutral-300">
                  Code sent to <strong>{email}</strong>. Enter it below to log
                  in to{" "}
                  <code className="font-mono text-xs">{subOrgId}</code>.
                </p>

                <div className="space-y-1">
                  <label
                    htmlFor="otpCode"
                    className="block text-xs font-medium text-neutral-700 dark:text-neutral-300"
                  >
                    Verification code
                  </label>
                  <input
                    id="otpCode"
                    type="text"
                    inputMode="text"
                    autoComplete="one-time-code"
                    required
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value.trim())}
                    placeholder="123456"
                    className="w-full rounded-lg border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 px-3 py-2 font-mono text-sm tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {loginError && (
                  <p className="text-sm text-red-600 dark:text-red-400">{loginError}</p>
                )}

                <div className="flex flex-col sm:flex-row gap-3">
                  <button
                    type="button"
                    onClick={resetLoginForm}
                    className="flex-1 rounded-lg border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-900 dark:text-neutral-100 font-medium px-4 py-2.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
                  >
                    Back
                  </button>
                  <button
                    type="submit"
                    disabled={isVerifying || !otpCode}
                    className="flex-1 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium px-4 py-2.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
                  >
                    {isVerifying ? "Verifying..." : "Verify & log in"}
                  </button>
                </div>
              </form>
            )}
          </div>
        )}
      </div>
    </main>
  );
}

export default function Home() {
  return <AuthStatus />;
}