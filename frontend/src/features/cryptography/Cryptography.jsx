import { useState } from "react";
import { LockKeyhole } from "lucide-react";
import { analysisService } from "../../services/analysisService";
import LoadingState from "../../components/common/LoadingState";
import ErrorMessage from "../../components/common/ErrorMessage";
import ResultCard from "../../components/common/ResultCard";

// ─── Shared Utilities ─────────────────────────────────────────────────────────

function TextInput({ label, value, onChange, placeholder, type = "text", rows }) {
  const baseClass =
    "w-full rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none";
  return (
    <div>
      {label && (
        <label className="mb-1.5 block text-xs font-semibold uppercase text-slate-500">
          {label}
        </label>
      )}
      {rows ? (
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          rows={rows}
          className={`${baseClass} resize-y`}
        />
      ) : (
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className={baseClass}
        />
      )}
    </div>
  );
}

function SubmitBtn({ loading, label = "Run", loadingLabel = "Running…", disabled }) {
  return (
    <button
      type="submit"
      disabled={loading || disabled}
      className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
    >
      {loading ? loadingLabel : label}
    </button>
  );
}

function AnalysisResultView({ data }) {
  if (!data) return null;
  return (
    <ResultCard title="Result" badge={data.risk_level}>
      {data.summary && (
        <p className="text-sm text-slate-300 leading-6">{data.summary}</p>
      )}
      {data.findings && data.findings.length > 0 && (
        <div className="mt-4 space-y-2">
          <p className="text-xs font-semibold uppercase text-slate-500">Findings</p>
          {data.findings.map((f, i) => (
            <div key={i} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs">
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="font-semibold text-slate-200">{f.title}</span>
                <span className="rounded-full border border-slate-600/40 bg-slate-600/15 px-2 py-0.5 text-xs font-semibold uppercase text-slate-400">
                  {f.severity}
                </span>
              </div>
              {f.description && <p className="text-slate-400 leading-5">{f.description}</p>}
              {f.evidence && (
                <pre className="mt-1 font-mono text-slate-500 whitespace-pre-wrap break-all">
                  {f.evidence}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
      {data.details && Object.keys(data.details).length > 0 && (
        <div className="mt-4">
          <p className="mb-2 text-xs font-semibold uppercase text-slate-500">Details</p>
          <pre className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs font-mono text-slate-300 overflow-auto whitespace-pre-wrap break-all">
            {JSON.stringify(data.details, null, 2)}
          </pre>
        </div>
      )}
      {data.errors && data.errors.length > 0 && (
        <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400">
          {data.errors.join(", ")}
        </div>
      )}
    </ResultCard>
  );
}

function useApi(apiFn) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const run = async (...args) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await apiFn(...args));
    } catch (err) {
      setError(err.message || "An error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return { loading, result, error, run, setError };
}

// ─── Hashes ───────────────────────────────────────────────────────────────────

function HashesTab() {
  const [text, setText] = useState("");
  const { loading, result, error, run, setError } = useApi(analysisService.generateHashes);
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim()); }}
      className="space-y-4"
    >
      <TextInput label="Input Text" value={text} onChange={setText} placeholder="e.g. admin, password123" />
      <SubmitBtn loading={loading} label="Generate Hashes" loadingLabel="Computing…" disabled={!text.trim()} />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Computing hash suite…" />}
      {result && (
        <ResultCard title="Computed Hashes">
          {result.details && Object.keys(result.details).length > 0 ? (
            <div className="grid gap-2">
              {Object.entries(result.details).map(([algo, hash]) => (
                <div key={algo} className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-3">
                  <span className="text-xs font-mono uppercase text-cyan-400">{algo}</span>
                  <div className="mt-1 font-mono text-xs break-all text-slate-200">{hash}</div>
                </div>
              ))}
            </div>
          ) : (
            <AnalysisResultView data={result} />
          )}
        </ResultCard>
      )}
    </form>
  );
}

// ─── Base64 ───────────────────────────────────────────────────────────────────

function Base64Tab() {
  const [subTab, setSubTab] = useState("encode");
  const [text, setText] = useState("");
  const enc = useApi(analysisService.base64Encode);
  const dec = useApi(analysisService.base64Decode);
  const active = subTab === "encode" ? enc : dec;
  const run = subTab === "encode" ? enc.run : dec.run;

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {["encode", "decode"].map((s) => (
          <button
            key={s}
            onClick={() => setText("")}
            type="button"
            className={`rounded-full px-3 py-1 text-xs font-medium transition ${subTab === s ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"}`}
            onClickCapture={() => setSubTab(s)}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      <form
        onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim()); }}
        className="space-y-4"
      >
        <TextInput
          label={subTab === "encode" ? "Plain Text" : "Base64 String"}
          value={text}
          onChange={setText}
          placeholder={subTab === "encode" ? "Text to encode…" : "Base64 to decode…"}
          rows={3}
        />
        <SubmitBtn loading={active.loading} label={subTab === "encode" ? "Encode" : "Decode"} disabled={!text.trim()} />
        {active.error && <ErrorMessage message={active.error} onDismiss={() => active.setError(null)} />}
        {active.loading && <LoadingState message="Processing…" />}
        <AnalysisResultView data={active.result} />
      </form>
    </div>
  );
}

// ─── Hash Identify ────────────────────────────────────────────────────────────

function HashIdentifyTab() {
  const [text, setText] = useState("");
  const { loading, result, error, run, setError } = useApi(analysisService.identifyHash);
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim()); }}
      className="space-y-4"
    >
      <TextInput label="Hash String" value={text} onChange={setText} placeholder="Paste a hash to identify…" />
      <SubmitBtn loading={loading} label="Identify Hash" loadingLabel="Identifying…" disabled={!text.trim()} />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Identifying hash algorithm…" />}
      <AnalysisResultView data={result} />
    </form>
  );
}

// ─── Cipher Identify ──────────────────────────────────────────────────────────

function CipherIdentifyTab() {
  const [text, setText] = useState("");
  const { loading, result, error, run, setError } = useApi(analysisService.identifyCipher);
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim()); }}
      className="space-y-4"
    >
      <TextInput label="Encoded / Ciphertext" value={text} onChange={setText} placeholder="Paste ciphertext or encoded string…" rows={3} />
      <SubmitBtn loading={loading} label="Identify Cipher" loadingLabel="Identifying…" disabled={!text.trim()} />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Identifying encoding/cipher…" />}
      <AnalysisResultView data={result} />
    </form>
  );
}

// ─── ROT Decode ───────────────────────────────────────────────────────────────

function RotDecodeTab() {
  const [text, setText] = useState("");
  const [shift, setShift] = useState(13);
  const { loading, result, error, run, setError } = useApi(
    (t, s) => analysisService.rotDecode(t, s)
  );
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim(), Number(shift)); }}
      className="space-y-4"
    >
      <TextInput label="Ciphertext" value={text} onChange={setText} placeholder="ROT-encoded text…" rows={3} />
      <div>
        <label className="mb-1.5 block text-xs font-semibold uppercase text-slate-500">
          Shift: <span className="text-cyan-400">{shift}</span>
        </label>
        <input
          type="range"
          min={0}
          max={25}
          value={shift}
          onChange={(e) => setShift(e.target.value)}
          className="w-full accent-cyan-500"
        />
        <div className="mt-1 flex justify-between text-xs text-slate-600">
          <span>0</span><span>25</span>
        </div>
      </div>
      <SubmitBtn loading={loading} label={`ROT-${shift} Decode`} loadingLabel="Decoding…" disabled={!text.trim()} />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Decoding ROT cipher…" />}
      <AnalysisResultView data={result} />
    </form>
  );
}

// ─── Morse ────────────────────────────────────────────────────────────────────

function MorseTab() {
  const [subTab, setSubTab] = useState("encode");
  const [text, setText] = useState("");
  const enc = useApi(analysisService.morseEncode);
  const dec = useApi(analysisService.morseDecode);
  const active = subTab === "encode" ? enc : dec;
  const run = subTab === "encode" ? enc.run : dec.run;

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {["encode", "decode"].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => { setSubTab(s); setText(""); }}
            className={`rounded-full px-3 py-1 text-xs font-medium transition ${subTab === s ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"}`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      <form
        onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim()); }}
        className="space-y-4"
      >
        <TextInput
          label={subTab === "encode" ? "Plain Text" : "Morse Code"}
          value={text}
          onChange={setText}
          placeholder={subTab === "encode" ? "Text to convert to Morse…" : ".- -... -.-. …"}
          rows={3}
        />
        <SubmitBtn loading={active.loading} label={subTab === "encode" ? "Encode to Morse" : "Decode Morse"} disabled={!text.trim()} />
        {active.error && <ErrorMessage message={active.error} onDismiss={() => active.setError(null)} />}
        {active.loading && <LoadingState message="Processing Morse…" />}
        <AnalysisResultView data={active.result} />
      </form>
    </div>
  );
}

// ─── Brainfuck ────────────────────────────────────────────────────────────────

function BrainfuckTab() {
  const [subTab, setSubTab] = useState("encode");
  const [text, setText] = useState("");
  const enc = useApi(analysisService.brainfuckEncode);
  const dec = useApi(analysisService.brainfuckDecode);
  const active = subTab === "encode" ? enc : dec;
  const run = subTab === "encode" ? enc.run : dec.run;

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {["encode", "decode"].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => { setSubTab(s); setText(""); }}
            className={`rounded-full px-3 py-1 text-xs font-medium transition ${subTab === s ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"}`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      <form
        onSubmit={(e) => { e.preventDefault(); if (text.trim()) run(text.trim()); }}
        className="space-y-4"
      >
        <TextInput
          label={subTab === "encode" ? "Plain Text" : "Brainfuck Code"}
          value={text}
          onChange={setText}
          placeholder={subTab === "encode" ? "Text to encode to Brainfuck…" : "+++++++++[...]…"}
          rows={4}
        />
        <SubmitBtn loading={active.loading} label={subTab === "encode" ? "Encode" : "Decode"} disabled={!text.trim()} />
        {active.error && <ErrorMessage message={active.error} onDismiss={() => active.setError(null)} />}
        {active.loading && <LoadingState message="Processing Brainfuck…" />}
        <AnalysisResultView data={active.result} />
      </form>
    </div>
  );
}

// ─── AES-GCM ─────────────────────────────────────────────────────────────────

function AesGcmTab() {
  const [subTab, setSubTab] = useState("encrypt");
  const [plaintext, setPlaintext] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [key, setKey] = useState("");
  const [nonce, setNonce] = useState("");
  const enc = useApi((pt, k) => analysisService.aesGcmEncrypt(pt, k));
  const dec = useApi((ct, k, n) => analysisService.aesGcmDecrypt(ct, k, n));

  const handleEncrypt = (e) => {
    e.preventDefault();
    if (plaintext.trim() && key.trim()) enc.run(plaintext.trim(), key.trim());
  };

  const handleDecrypt = (e) => {
    e.preventDefault();
    if (ciphertext.trim() && key.trim() && nonce.trim())
      dec.run(ciphertext.trim(), key.trim(), nonce.trim());
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {["encrypt", "decrypt"].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setSubTab(s)}
            className={`rounded-full px-3 py-1 text-xs font-medium transition ${subTab === s ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"}`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      {subTab === "encrypt" ? (
        <form onSubmit={handleEncrypt} className="space-y-4">
          <TextInput label="Plaintext" value={plaintext} onChange={setPlaintext} placeholder="Text to encrypt…" rows={3} />
          <TextInput label="Key (hex or passphrase)" value={key} onChange={setKey} placeholder="Encryption key…" />
          <SubmitBtn loading={enc.loading} label="Encrypt" loadingLabel="Encrypting…" disabled={!plaintext.trim() || !key.trim()} />
          {enc.error && <ErrorMessage message={enc.error} onDismiss={() => enc.setError(null)} />}
          {enc.loading && <LoadingState message="Encrypting with AES-GCM…" />}
          <AnalysisResultView data={enc.result} />
        </form>
      ) : (
        <form onSubmit={handleDecrypt} className="space-y-4">
          <TextInput label="Ciphertext" value={ciphertext} onChange={setCiphertext} placeholder="Ciphertext (hex)…" rows={3} />
          <TextInput label="Key" value={key} onChange={setKey} placeholder="Decryption key…" />
          <TextInput label="Nonce" value={nonce} onChange={setNonce} placeholder="Nonce (hex)…" />
          <SubmitBtn loading={dec.loading} label="Decrypt" loadingLabel="Decrypting…" disabled={!ciphertext.trim() || !key.trim() || !nonce.trim()} />
          {dec.error && <ErrorMessage message={dec.error} onDismiss={() => dec.setError(null)} />}
          {dec.loading && <LoadingState message="Decrypting with AES-GCM…" />}
          <AnalysisResultView data={dec.result} />
        </form>
      )}
    </div>
  );
}

// ─── RSA ─────────────────────────────────────────────────────────────────────

function RsaTab() {
  const [subTab, setSubTab] = useState("keygen");
  const keygen = useApi(analysisService.rsaGenerateKeyPair);
  const [signValue, setSignValue] = useState("");
  const [privKey, setPrivKey] = useState("");
  const sign = useApi((v, k) => analysisService.rsaSign(v, k));
  const [verifyValue, setVerifyValue] = useState("");
  const [pubKey, setPubKey] = useState("");
  const [signature, setSignature] = useState("");
  const verify = useApi((v, k, s) => analysisService.rsaVerify(v, k, s));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {["keygen", "sign", "verify"].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setSubTab(s)}
            className={`rounded-full px-3 py-1 text-xs font-medium transition ${subTab === s ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"}`}
          >
            {s === "keygen" ? "Key Pair" : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {subTab === "keygen" && (
        <div className="space-y-4">
          <p className="text-sm text-slate-400">Generate a new RSA key pair.</p>
          <button
            type="button"
            onClick={() => keygen.run()}
            disabled={keygen.loading}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
          >
            {keygen.loading ? "Generating…" : "Generate Key Pair"}
          </button>
          {keygen.error && <ErrorMessage message={keygen.error} onDismiss={() => keygen.setError(null)} />}
          {keygen.loading && <LoadingState message="Generating RSA key pair…" />}
          <AnalysisResultView data={keygen.result} />
        </div>
      )}

      {subTab === "sign" && (
        <form
          onSubmit={(e) => { e.preventDefault(); if (signValue.trim() && privKey.trim()) sign.run(signValue.trim(), privKey.trim()); }}
          className="space-y-4"
        >
          <TextInput label="Value to Sign" value={signValue} onChange={setSignValue} placeholder="Message or hash to sign…" rows={2} />
          <TextInput label="Private Key (PEM)" value={privKey} onChange={setPrivKey} placeholder="-----BEGIN RSA PRIVATE KEY-----" rows={6} />
          <SubmitBtn loading={sign.loading} label="Sign" loadingLabel="Signing…" disabled={!signValue.trim() || !privKey.trim()} />
          {sign.error && <ErrorMessage message={sign.error} onDismiss={() => sign.setError(null)} />}
          {sign.loading && <LoadingState message="Signing…" />}
          <AnalysisResultView data={sign.result} />
        </form>
      )}

      {subTab === "verify" && (
        <form
          onSubmit={(e) => { e.preventDefault(); if (verifyValue.trim() && pubKey.trim() && signature.trim()) verify.run(verifyValue.trim(), pubKey.trim(), signature.trim()); }}
          className="space-y-4"
        >
          <TextInput label="Value" value={verifyValue} onChange={setVerifyValue} placeholder="Original message or hash…" rows={2} />
          <TextInput label="Public Key (PEM)" value={pubKey} onChange={setPubKey} placeholder="-----BEGIN PUBLIC KEY-----" rows={5} />
          <TextInput label="Signature (hex/base64)" value={signature} onChange={setSignature} placeholder="Signature to verify…" rows={3} />
          <SubmitBtn loading={verify.loading} label="Verify Signature" loadingLabel="Verifying…" disabled={!verifyValue.trim() || !pubKey.trim() || !signature.trim()} />
          {verify.error && <ErrorMessage message={verify.error} onDismiss={() => verify.setError(null)} />}
          {verify.loading && <LoadingState message="Verifying signature…" />}
          <AnalysisResultView data={verify.result} />
        </form>
      )}
    </div>
  );
}

// ─── Token Generator ──────────────────────────────────────────────────────────

function TokenGenTab() {
  const [bytes, setBytes] = useState(32);
  const { loading, result, error, run, setError } = useApi(
    (b) => analysisService.generateToken(b)
  );
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); run(Number(bytes)); }}
      className="space-y-4"
    >
      <div>
        <label className="mb-1.5 block text-xs font-semibold uppercase text-slate-500">
          Number of Bytes
        </label>
        <input
          type="number"
          min={1}
          max={512}
          value={bytes}
          onChange={(e) => setBytes(e.target.value)}
          className="w-32 rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
        />
      </div>
      <SubmitBtn loading={loading} label="Generate Token" loadingLabel="Generating…" />
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <LoadingState message="Generating secure token…" />}
      <AnalysisResultView data={result} />
    </form>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const TABS = [
  { id: "hashes", label: "Hashes" },
  { id: "base64", label: "Base64" },
  { id: "hash-identify", label: "Hash Identify" },
  { id: "cipher-identify", label: "Cipher Identify" },
  { id: "rot", label: "ROT Decode" },
  { id: "morse", label: "Morse" },
  { id: "brainfuck", label: "Brainfuck" },
  { id: "aes-gcm", label: "AES-GCM" },
  { id: "rsa", label: "RSA" },
  { id: "token", label: "Token Gen" },
];

export default function Cryptography() {
  const [activeTab, setActiveTab] = useState("hashes");

  return (
    <div className="max-w-4xl space-y-6">
      {/* Header */}
      <div>
        <h2 className="flex items-center gap-2 text-2xl font-bold">
          <LockKeyhole className="text-cyan-400" size={24} /> Cryptography Suite
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Hashing, encoding, encryption, and cipher operations — all locally processed via the backend.
        </p>
      </div>

      {/* Tab nav */}
      <div className="flex flex-wrap gap-2">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`rounded-full px-4 py-1.5 text-sm font-medium transition ${
              activeTab === tab.id
                ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panel */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 p-6">
        {activeTab === "hashes" && <HashesTab />}
        {activeTab === "base64" && <Base64Tab />}
        {activeTab === "hash-identify" && <HashIdentifyTab />}
        {activeTab === "cipher-identify" && <CipherIdentifyTab />}
        {activeTab === "rot" && <RotDecodeTab />}
        {activeTab === "morse" && <MorseTab />}
        {activeTab === "brainfuck" && <BrainfuckTab />}
        {activeTab === "aes-gcm" && <AesGcmTab />}
        {activeTab === "rsa" && <RsaTab />}
        {activeTab === "token" && <TokenGenTab />}
      </div>
    </div>
  );
}
