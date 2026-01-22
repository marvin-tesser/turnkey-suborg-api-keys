"use client";
import { useState } from "react";
import { useTurnkey, AuthState } from "@turnkey/react-wallet-kit";

// Helper to convert ArrayBuffer to hex string
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Export CryptoKeyPair to hex strings for display
async function exportKeyPairToHex(keyPair: CryptoKeyPair): Promise<{ publicKey: string; privateKey: string }> {
  // Export public key as raw (uncompressed point with 04 prefix)
  const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  // Keep the full uncompressed public key (04 prefix + x + y coordinates)
  const publicKeyHex = bufferToHex(publicKeyRaw);

  // Export private key as JWK to get the 'd' value
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  // Convert base64url 'd' value to hex
  const privateKeyBytes = Uint8Array.from(
    atob(privateKeyJwk.d!.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );
  const privateKeyHex = bufferToHex(privateKeyBytes.buffer);

  return { publicKey: publicKeyHex, privateKey: privateKeyHex };
}

function AuthStatus() {
  const { authState, user, session, handleLogin, httpClient } = useTurnkey();
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

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
    <div>
      {authState === AuthState.Authenticated ? (
        <div>
          <p>Welcome back, {user?.userName}!</p>
          <p>Organization ID: {session?.organizationId}</p>
          
          <button onClick={handleGenerateKeyPair} disabled={isGenerating}>
            {isGenerating ? "Generating..." : "Generate API Key Pair"}
          </button>
          
          {publicKey && (
            <div>
              <p><strong>Public Key:</strong></p>
              <code style={{ wordBreak: "break-all" }}>{publicKey}</code>
            </div>
          )}
          
          {privateKey && (
            <div>
              <p><strong>Private Key:</strong></p>
              <code style={{ wordBreak: "break-all" }}>{privateKey}</code>
            </div>
          )}
        </div>
      ) : (
        <button onClick={() => handleLogin()}>Login / Sign Up</button>
      )}
    </div>
  );
}

export default function Home() {
  return <AuthStatus />;
}