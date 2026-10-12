
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Level = "critical" | "high" | "medium" | "low" | "info";
type HeaderResult = { name: string; value?: string | null; present: boolean };
type TlsResult = {
  valid: boolean;
  validTo?: string | null;
  validFrom?: string | null;
  issuer?: string | null;
  subject?: string | null;
  daysRemaining?: number | null;
  error?: string | null;
};
type ReputationResult = {
  safe?: boolean;
  checked?: boolean;
  threats?: unknown[];
  matches?: unknown[];
  error?: string | null;
  status?: string;
  provider?: string;
  message?: string;
  checkedUrls?: string[];
};
type ScanResult = {
  success?: boolean;
  target?: string;
  error?: string;
  results: {
    https: { connected: boolean; status?: number | null };
    headers: { count: number; results: HeaderResult[] };
    redirects: { count: number; finalUrl: string; chain: string[] };
    tls: TlsResult;
    reputation: ReputationResult;
    notice?: string;
  };
};
type Finding = {
  id: string;
  title: string;
  description: string;
  recommendation: string;
  level: Level;
};
type ScanHistoryItem = {
  id: string;
  url: string;
  score: number;
  date: string;
  findings: number;
};

const EMPTY_TLS: TlsResult = {
  valid: false,
  validTo: null,
  validFrom: null,
  issuer: null,
  subject: null,
  daysRemaining: null,
  error: "A API não retornou os dados do certificado TLS.",
};

const EMPTY_REPUTATION: ReputationResult = {
  safe: undefined,
  checked: false,
  threats: [],
  matches: [],
  error: "A API não retornou os dados de reputação.",
};

const HEADER_GUIDANCE: Record<
  string,
  { title: string; description: string; recommendation: string; level: Level }
> = {
  "strict-transport-security": {
    title: "HSTS ausente",
    description: "O cabeçalho Strict-Transport-Security não foi identificado na resposta HTTPS.",
    recommendation: "Quando o site estiver preparado para operar exclusivamente com HTTPS, configure HSTS com um período adequado.",
    level: "medium",
  },
  "content-security-policy": {
    title: "Content Security Policy ausente",
    description: "Não foi identificado um Content-Security-Policy para restringir as origens de conteúdo carregado.",
    recommendation: "Configure uma CSP compatível com os recursos legítimos da aplicação. Teste a política antes de aplicá-la.",
    level: "medium",
  },
  "x-content-type-options": {
    title: "X-Content-Type-Options ausente",
    description: "Não foi identificada a instrução para impedir a interpretação automática do tipo de conteúdo.",
    recommendation: 'Configure X-Content-Type-Options com o valor "nosniff".',
    level: "low",
  },
  "x-frame-options": {
    title: "Proteção contra enquadramento ausente",
    description: "Não foi identificado X-Frame-Options nem uma diretiva frame-ancestors na CSP.",
    recommendation: "Configure X-Frame-Options com DENY ou SAMEORIGIN, ou uma política CSP frame-ancestors adequada.",
    level: "medium",
  },
  "referrer-policy": {
    title: "Referrer-Policy ausente",
    description: "A política de referência não foi explicitamente definida na resposta.",
    recommendation: 'Avalie configurar Referrer-Policy com "strict-origin-when-cross-origin" ou outra política adequada.',
    level: "low",
  },
  "permissions-policy": {
    title: "Permissions-Policy ausente",
    description: "Não foi identificada uma política explícita para controlar recursos do navegador.",
    recommendation: "Avalie limitar recursos como câmera, microfone e geolocalização quando não forem necessários.",
    level: "info",
  },
};

const LEVEL_ORDER: Record<Level, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const LEVEL_LABEL: Record<Level, string> = {
  critical: "CRÍTICO",
  high: "ALTO",
  medium: "MÉDIO",
  low: "BAIXO",
  info: "INFO",
};

function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("Digite um endereço para iniciar a análise.");

  const candidate = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("O endereço informado não é uma URL válida.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Utilize um endereço HTTP ou HTTPS.");
  }
  if (!parsed.hostname || !parsed.hostname.includes(".")) {
    throw new Error("Informe um domínio válido, como exemplo.com.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs com usuário ou senha não são aceitas.");
  }

  return parsed.toString();
}

/**
 * Normaliza a resposta do backend antes de usá-la na interface.
 * Assim, uma propriedade ausente não causa erros como tls.valid.
 */
function normalizeScanResult(raw: unknown, fallbackUrl: string): ScanResult {
  if (!raw || typeof raw !== "object") {
    throw new Error("A API retornou uma resposta inválida.");
  }

  const data = raw as Record<string, any>;
  if (data.error) throw new Error(String(data.error));

  const root = data.results && typeof data.results === "object"
    ? data.results
    : {};

  const tlsData = root.tls ?? data.tls ?? EMPTY_TLS;
  const reputationData = root.reputation ?? data.reputation ?? EMPTY_REPUTATION;
  const headerData = root.headers ?? {};
  const redirectData = root.redirects ?? {};

  const headers: HeaderResult[] = Array.isArray(headerData.results)
    ? headerData.results.filter(
        (item: unknown) =>
          item &&
          typeof item === "object" &&
          typeof (item as HeaderResult).name === "string",
      )
    : [];

  const threats = Array.isArray(reputationData.threats)
    ? reputationData.threats
    : Array.isArray(reputationData.matches)
      ? reputationData.matches
      : [];

  const reputation: ReputationResult = {
    ...reputationData,
    threats,
    matches: Array.isArray(reputationData.matches)
      ? reputationData.matches
      : [],
    safe:
      typeof reputationData.safe === "boolean"
        ? reputationData.safe
        : reputationData.status === "clean"
          ? true
          : reputationData.status === "flagged"
            ? false
            : undefined,
    checked:
      typeof reputationData.checked === "boolean"
        ? reputationData.checked
        : ["clean", "flagged"].includes(reputationData.status),
    error:
      reputationData.error ??
      (["error", "not_configured"].includes(reputationData.status)
        ? reputationData.message ?? "Consulta de reputação inconclusiva."
        : null),
  };

  const finalUrl =
    typeof redirectData.finalUrl === "string"
      ? redirectData.finalUrl
      : fallbackUrl;

  const rawChain = Array.isArray(redirectData.chain)
    ? redirectData.chain
    : [];

  const chain = rawChain
    .map((item: unknown) => {
      if (typeof item === "string") return item;
      if (item && typeof item === "object") {
        const entry = item as { url?: unknown; location?: unknown };
        if (typeof entry.url === "string") return entry.url;
        if (typeof entry.location === "string") return entry.location;
      }
      return "";
    })
    .filter(Boolean);

  const tls: TlsResult = {
    ...EMPTY_TLS,
    ...(tlsData && typeof tlsData === "object" ? tlsData : {}),
    valid: tlsData?.valid === true,
  };

  return {
    success: data.success !== false,
    target: typeof data.target === "string"
      ? data.target
      : typeof data.domain === "string"
        ? data.domain
        : fallbackUrl,
    results: {
      https: {
        connected: root.https?.connected === true,
        status: typeof root.https?.status === "number"
          ? root.https.status
          : null,
      },
      headers: {
        count: typeof headerData.count === "number"
          ? headerData.count
          : typeof headerData.present === "number"
            ? headerData.present
            : headers.filter((item) => item.present).length,
        results: headers,
      },
      redirects: {
        count: typeof redirectData.count === "number"
          ? redirectData.count
          : Math.max(0, chain.length - 1),
        finalUrl,
        chain,
      },
      tls,
      reputation,
      notice:
        typeof root.notice === "string"
          ? root.notice
          : typeof data.notice === "string"
            ? data.notice
            : "Os resultados são indicativos e não garantem que o domínio esteja livre de riscos.",
    },
  };
}

function getPrimaryLevel(findings: Finding[]): Level {
  if (!findings.length) return "info";
  return findings.reduce<Level>(
    (highest, finding) =>
      LEVEL_ORDER[finding.level] > LEVEL_ORDER[highest]
        ? finding.level
        : highest,
    "info",
  );
}

function getPrimaryFinding(findings: Finding[]): Finding | undefined {
  const highest = getPrimaryLevel(findings);
  return findings.find((finding) => finding.level === highest);
}

function getFindings(result: ScanResult): Finding[] {
  const findings: Finding[] = [];
  const { headers, https, redirects } = result.results;
  const tls = result.results.tls ?? EMPTY_TLS;
  const reputation = result.results.reputation ?? EMPTY_REPUTATION;

  let finalUrlUsesHttps = https.connected;
  try {
    finalUrlUsesHttps = new URL(redirects.finalUrl).protocol === "https:";
  } catch {
    // Mantém o valor inferido da conexão caso a URL final seja inválida.
  }

  const headerResults = headers?.results ?? [];
  const csp = headerResults.find(
    (header) =>
      header.name.toLowerCase() === "content-security-policy" &&
      header.present,
  );

  const cspProtectsFraming =
    Boolean(csp?.value) &&
    /(?:^|;)\s*frame-ancestors(?:\s|;|$)/i.test(csp?.value ?? "");

  for (const header of headerResults) {
    if (header.present) continue;
    const name = header.name.toLowerCase();

    if (name === "strict-transport-security" && !finalUrlUsesHttps) continue;
    if (name === "x-frame-options" && cspProtectsFraming) continue;

    const guidance = HEADER_GUIDANCE[name];
    if (!guidance) continue;

    findings.push({ id: `header-${name}`, ...guidance });
  }

  if (!finalUrlUsesHttps) {
    findings.push({
      id: "https-not-confirmed",
      title: "HTTPS não confirmado na URL final",
      description: "Após a análise dos redirecionamentos, o endereço final não utiliza HTTPS.",
      recommendation: "Se o serviço oferece acesso web, configure HTTPS com um certificado válido e redirecione o tráfego HTTP para HTTPS.",
      level: "high",
    });
  }

  if (!tls.valid && tls.validTo) {
    findings.push({
      id: "tls-invalid",
      title: "Certificado TLS não validado",
      description: tls.error ?? "O certificado não passou em todas as verificações realizadas.",
      recommendation: "Verifique a cadeia de confiança, o hostname, o período de validade e a configuração TLS do servidor.",
      level: "high",
    });
  } else if (tls.error && finalUrlUsesHttps) {
    findings.push({
      id: "tls-unavailable",
      title: "Validação do certificado inconclusiva",
      description: tls.error,
      recommendation: "Confirme a conectividade HTTPS e execute a análise novamente. Uma falha de consulta não comprova, por si só, uma vulnerabilidade.",
      level: "medium",
    });
  }

  const hasThreats =
    (Array.isArray(reputation.threats) && reputation.threats.length > 0) ||
    (Array.isArray(reputation.matches) && reputation.matches.length > 0);

  if (hasThreats || reputation.safe === false) {
    findings.push({
      id: "reputation-threat",
      title: "Alerta de reputação",
      description: "O serviço de reputação sinalizou um possível risco para o endereço analisado.",
      recommendation: "Evite interagir com o endereço até verificar o alerta. Confirme os resultados na fonte de reputação e investigue o domínio.",
      level: "critical",
    });
  } else if (
    reputation.error &&
    !hasThreats &&
    reputation.safe === undefined
  ) {
    findings.push({
      id: "reputation-unavailable",
      title: "Reputação inconclusiva",
      description: reputation.error,
      recommendation: "Execute a análise novamente. A indisponibilidade da consulta não significa que o domínio seja malicioso ou seguro.",
      level: "info",
    });
  }

  return findings.sort(
    (a, b) => LEVEL_ORDER[b.level] - LEVEL_ORDER[a.level],
  );
}

function calculateScore(findings: Finding[]): number {
  const deductions: Record<Level, number> = {
    critical: 35,
    high: 20,
    medium: 10,
    low: 5,
    info: 0,
  };

  return Math.max(
    0,
    Math.min(
      100,
      100 - findings.reduce((sum, item) => sum + deductions[item.level], 0),
    ),
  );
}

function getScoreLabel(score: number): string {
  if (score >= 85) return "EXPOSIÇÃO BAIXA";
  if (score >= 65) return "EXPOSIÇÃO MODERADA";
  if (score >= 40) return "EXPOSIÇÃO ELEVADA";
  return "EXPOSIÇÃO CRÍTICA";
}

function getLevelClass(level: Level): string {
  switch (level) {
    case "critical": return "border-red-500/40 bg-red-500/10 text-red-300";
    case "high": return "border-orange-500/40 bg-orange-500/10 text-orange-300";
    case "medium": return "border-yellow-500/40 bg-yellow-500/10 text-yellow-200";
    case "low": return "border-cyan-500/30 bg-cyan-500/10 text-cyan-200";
    default: return "border-slate-500/30 bg-slate-500/10 text-slate-300";
  }
}

function formatDate(value: string): string {
  try {
    return new Date(value).toLocaleString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return value;
  }
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [activeTab, setActiveTab] = useState<"overview" | "headers" | "connection">("overview");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("nexus-zero-history");
      if (saved) {
        const parsed: unknown = JSON.parse(saved);
        if (Array.isArray(parsed)) setHistory(parsed as ScanHistoryItem[]);
      }
    } catch {
      // Histórico local opcional.
    }
  }, []);

  const findings = useMemo(() => result ? getFindings(result) : [], [result]);
  const score = useMemo(() => calculateScore(findings), [findings]);
  const primaryFinding = useMemo(() => getPrimaryFinding(findings), [findings]);

  const counts = useMemo(() => {
    const count = (level: Level) => findings.filter((item) => item.level === level).length;
    return {
      critical: count("critical"),
      high: count("high"),
      medium: count("medium"),
      low: count("low"),
      info: count("info"),
      total: findings.length,
    };
  }, [findings]);

  const saveHistory = useCallback((item: ScanHistoryItem) => {
    setHistory((previous) => {
      const next = [item, ...previous.filter((entry) => entry.url !== item.url)].slice(0, 8);
      try {
        localStorage.setItem("nexus-zero-history", JSON.stringify(next));
      } catch {
        // A análise continua se o armazenamento estiver indisponível.
      }
      return next;
    });
  }, []);

  const runScan = useCallback(async (providedUrl?: string) => {
    let target: string;
    try {
      target = normalizeUrl(providedUrl ?? url);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Confira o endereço informado.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setExpandedFinding(null);
    setActiveTab("overview");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });

      let raw: unknown;
      try {
        raw = await response.json();
      } catch {
        throw new Error("A API retornou uma resposta que não é JSON válido.");
      }

      const data = normalizeScanResult(raw, target);
      if (!response.ok || data.success === false) {
        throw new Error(data.error || "Não foi possível concluir a análise.");
      }

      setResult(data);
      const nextFindings = getFindings(data);
      saveHistory({
        id: `${Date.now()}`,
        url: target,
        score: calculateScore(nextFindings),
        date: new Date().toISOString(),
        findings: nextFindings.length,
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Erro inesperado ao analisar o endereço.");
    } finally {
      setLoading(false);
    }
  }, [url, saveHistory]);

  const copyReport = useCallback(async () => {
    if (!result) return;

    const report = [
      "NEXUS//ZERO SECURITY — RELATÓRIO",
      `Alvo: ${result.target ?? url}`,
      `URL final: ${result.results.redirects.finalUrl}`,
      `Pontuação de segurança: ${score}/100`,
      `Achados: ${findings.length}`,
      "",
      ...findings.map((finding) =>
        `[${LEVEL_LABEL[finding.level]}] ${finding.title}\n${finding.description}\nRecomendação: ${finding.recommendation}`,
      ),
    ].join("\n\n");

    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("Não foi possível copiar o relatório neste navegador.");
    }
  }, [result, url, score, findings]);

  const clearHistory = useCallback(() => {
    setHistory([]);
    try {
      localStorage.removeItem("nexus-zero-history");
    } catch {
      // Ignora falhas locais.
    }
  }, []);

  const headerResults = result?.results.headers.results ?? [];
  const tls = result?.results.tls ?? EMPTY_TLS;
  const reputation = result?.results.reputation ?? EMPTY_REPUTATION;

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#05070b] text-slate-200 selection:bg-cyan-300 selection:text-black">
      <div className="pointer-events-none fixed inset-0">
        <div className="absolute -left-40 -top-40 h-[520px] w-[520px] rounded-full bg-cyan-500/[0.07] blur-[140px]" />
        <div className="absolute -right-40 top-1/3 h-[520px] w-[520px] rounded-full bg-blue-600/[0.07] blur-[150px]" />
        <div className="absolute bottom-0 left-1/3 h-[400px] w-[400px] rounded-full bg-violet-600/[0.05] blur-[140px]" />
        <div className="absolute inset-0 bg-[linear-gradient(rgba(34,211,238,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,0.025)_1px,transparent_1px)] bg-[size:48px_48px]" />
      </div>

      <div className="relative mx-auto max-w-[1400px] px-4 pb-12 sm:px-6 lg:px-10">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.08] py-5">
          <a href="#top" className="flex items-center gap-3" aria-label="Nexus Zero início">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-300/30 bg-cyan-300/[0.08] font-mono text-lg font-black text-cyan-200 shadow-[0_0_25px_rgba(34,211,238,0.10)]">
              N<span className="text-white">/</span>
            </div>
            <div>
              <div className="font-mono text-sm font-bold tracking-[0.18em] text-white">
                NEXUS<span className="text-cyan-300">//</span>ZERO
              </div>
              <div className="mt-0.5 text-[10px] uppercase tracking-[0.25em] text-slate-500">
                Security intelligence
              </div>
            </div>
          </a>
          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/[0.05] px-3 py-2 text-[10px] font-semibold uppercase tracking-widest text-emerald-300 sm:flex">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-300" />
              Scanner online
            </div>
            <button type="button" onClick={() => setShowHistory((value) => !value)} className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-300 transition hover:border-cyan-300/40 hover:text-cyan-200">
              {showHistory ? "Fechar histórico" : "Histórico"}
              {history.length > 0 && <span className="ml-2 rounded bg-cyan-300/10 px-1.5 py-0.5 font-mono text-cyan-200">{history.length}</span>}
            </button>
          </div>
        </header>

        <section id="top" className="grid gap-10 pb-12 pt-12 lg:grid-cols-[1.1fr_0.9fr] lg:items-center lg:pb-16 lg:pt-20">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/[0.05] px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-200">
              <span className="text-cyan-300">✳</span> Web exposure analyzer
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight text-white sm:text-5xl lg:text-6xl">
              Enxergue além da
              <span className="block bg-gradient-to-r from-cyan-300 via-sky-400 to-blue-500 bg-clip-text pb-2 text-transparent">
                superfície digital.
              </span>
            </h1>
            <p className="mt-6 max-w-xl text-sm leading-7 text-slate-400 sm:text-base">
              Analise a exposição de um domínio, inspecione cabeçalhos HTTP, redirecionamentos,
              certificado TLS e indicadores de reputação em uma única interface.
            </p>
            <div className="mt-8 flex flex-wrap gap-x-6 gap-y-3 text-xs text-slate-500">
              {["HTTP headers", "TLS inspection", "Redirect analysis", "Threat reputation"].map((item) => (
                <span key={item} className="flex items-center gap-2"><span className="text-cyan-300">◇</span>{item}</span>
              ))}
            </div>
          </div>

          <div className="relative">
            <div className="absolute -inset-3 rounded-3xl bg-cyan-400/[0.04] blur-2xl" />
            <div className="relative rounded-2xl border border-cyan-300/20 bg-[#090e16]/90 p-5 shadow-[0_0_60px_rgba(8,145,178,0.08)] sm:p-7">
              <div className="mb-6 flex items-start justify-between gap-4">
                <div>
                  <div className="font-mono text-xs uppercase tracking-[0.18em] text-cyan-300">// Target analysis</div>
                  <h2 className="mt-2 text-lg font-semibold text-white">Iniciar diagnóstico</h2>
                  <p className="mt-1 text-xs text-slate-500">Insira o domínio que deseja analisar.</p>
                </div>
                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-300/[0.07] font-mono text-xl text-cyan-200">⌕</div>
              </div>

              <form onSubmit={(event) => { event.preventDefault(); void runScan(); }}>
                <label htmlFor="target-url" className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Target URL</label>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <div className="flex min-w-0 flex-1 items-center rounded-xl border border-white/10 bg-black/30 px-3 transition focus-within:border-cyan-300/50">
                    <span className="mr-2 font-mono text-sm text-cyan-300">↗</span>
                    <input id="target-url" type="text" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://exemplo.com" autoComplete="url" spellCheck={false} className="w-full min-w-0 bg-transparent py-3.5 text-sm text-white outline-none placeholder:text-slate-600" />
                  </div>
                  <button type="submit" disabled={loading} className="rounded-xl bg-cyan-300 px-5 py-3 text-xs font-bold uppercase tracking-[0.12em] text-[#041015] transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50">
                    {loading ? "Analisando..." : "Executar scan"}
                  </button>
                </div>
              </form>

              {error && <div role="alert" className="mt-4 rounded-xl border border-red-400/20 bg-red-400/[0.06] p-3 text-xs leading-5 text-red-300"><span className="mr-2 font-bold">!</span>{error}</div>}

              {loading && <div className="mt-5 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.04] p-4">
                <div className="mb-3 flex items-center justify-between text-xs"><span className="text-cyan-200">Inspecionando o alvo...</span><span className="font-mono text-slate-500">RUNNING</span></div>
                <div className="h-1 overflow-hidden rounded-full bg-white/10"><div className="h-full w-1/2 animate-pulse rounded-full bg-cyan-300" /></div>
                <p className="mt-3 text-[11px] leading-5 text-slate-500">Verificando conexão, redirecionamentos, cabeçalhos e informações TLS.</p>
              </div>}

              <div className="mt-5 border-t border-white/[0.07] pt-4">
                <div className="mb-2 text-[10px] uppercase tracking-[0.16em] text-slate-600">Sugestões para teste</div>
                <div className="flex flex-wrap gap-2">
                  {["https://google.com", "https://github.com"].map((suggestion) => (
                    <button key={suggestion} type="button" onClick={() => { setUrl(suggestion); void runScan(suggestion); }} disabled={loading} className="rounded-lg border border-white/[0.08] px-2.5 py-1.5 font-mono text-[10px] text-slate-400 transition hover:border-cyan-300/30 hover:text-cyan-200 disabled:opacity-50">
                      {suggestion.replace("https://", "")}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {showHistory && <section className="mb-8 rounded-2xl border border-white/10 bg-[#090e16]/90 p-5 sm:p-6">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div><div className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300">// Local records</div><h2 className="mt-1 text-base font-semibold text-white">Histórico de análises</h2></div>
            {history.length > 0 && <button type="button" onClick={clearHistory} className="text-xs text-slate-500 transition hover:text-red-300">Limpar histórico</button>}
          </div>
          {history.length === 0 ? <p className="rounded-xl border border-dashed border-white/10 p-6 text-center text-xs text-slate-500">Nenhuma análise salva neste navegador.</p> : <div className="space-y-2">
            {history.map((item) => <div key={item.id} className="flex flex-col justify-between gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 sm:flex-row sm:items-center">
              <div className="min-w-0"><div className="truncate font-mono text-sm text-slate-200">{item.url}</div><div className="mt-1 text-[10px] text-slate-500">{formatDate(item.date)} · {item.findings} achados</div></div>
              <div className="flex items-center gap-3"><span className="font-mono text-sm text-cyan-200">{item.score}/100</span><button type="button" onClick={() => { setUrl(item.url); void runScan(item.url); }} disabled={loading} className="rounded-lg border border-white/10 px-3 py-2 text-[10px] uppercase tracking-wider text-slate-300 hover:border-cyan-300/30 hover:text-cyan-200 disabled:opacity-50">Reanalisar</button></div>
            </div>)}
          </div>}
          <p className="mt-4 text-[10px] leading-5 text-slate-600">O histórico é armazenado localmente neste navegador; não é um registro centralizado no servidor.</p>
        </section>}

        {result && <section className="space-y-6">
          <div className="flex flex-wrap items-end justify-between gap-4 border-b border-white/[0.08] pb-5">
            <div className="min-w-0"><div className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-300">// Analysis output</div><h2 className="mt-2 text-2xl font-semibold text-white">Relatório de segurança</h2><p className="mt-2 max-w-2xl break-all font-mono text-xs text-slate-500">{result.target ?? url}</p></div>
            <button type="button" onClick={() => void copyReport()} className="rounded-lg border border-cyan-300/25 bg-cyan-300/[0.05] px-4 py-2.5 text-xs font-medium text-cyan-200 transition hover:bg-cyan-300/10">{copied ? "Relatório copiado" : "Copiar relatório"}</button>
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard label="Security index" symbol="◈">
              <div className="mt-4 flex items-end gap-2"><span className="font-mono text-4xl font-semibold text-white">{score}</span><span className="pb-1 text-sm text-slate-500">/100</span></div>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-white/[0.07]"><div className={`h-full rounded-full transition-all ${score >= 85 ? "bg-emerald-300" : score >= 65 ? "bg-cyan-300" : score >= 40 ? "bg-yellow-300" : "bg-red-400"}`} style={{ width: `${score}%` }} /></div>
              <div className="mt-2 text-[10px] uppercase tracking-wider text-slate-500">{getScoreLabel(score)}</div>
            </MetricCard>
            <MetricCard label="Security findings" symbol="⌁">
              <div className="mt-4 font-mono text-4xl font-semibold text-white">{counts.total}</div><div className="mt-2 text-xs text-slate-500">Achados identificados</div>
              <div className="mt-4 flex flex-wrap gap-2">
                {counts.critical > 0 && <CountTag color="red" text={`${counts.critical} crítico(s)`} />}
                {counts.high > 0 && <CountTag color="orange" text={`${counts.high} alto(s)`} />}
                {counts.medium > 0 && <CountTag color="yellow" text={`${counts.medium} médio(s)`} />}
                {counts.low + counts.info > 0 && <CountTag color="cyan" text={`${counts.low + counts.info} outro(s)`} />}
              </div>
            </MetricCard>
            <MetricCard label="HTTPS" symbol="⌑">
              <div className="mt-4 flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${result.results.https.connected ? "bg-emerald-300 shadow-[0_0_12px_rgba(110,231,183,0.5)]" : "bg-orange-300"}`} /><span className="text-lg font-semibold text-white">{result.results.https.connected ? "Detectado" : "Não confirmado"}</span></div>
              <div className="mt-2 text-xs text-slate-500">Status HTTP: {result.results.https.status ?? "Indisponível"}</div><div className="mt-4 text-[10px] leading-5 text-slate-500">Refere-se ao protocolo da URL final analisada.</div>
            </MetricCard>
            <MetricCard label="Redirect chain" symbol="⇢">
              <div className="mt-4 font-mono text-4xl font-semibold text-white">{result.results.redirects.count}</div><div className="mt-2 text-xs text-slate-500">Redirecionamento(s) identificado(s)</div><div className="mt-4 break-all font-mono text-[10px] leading-5 text-cyan-200/80">{result.results.redirects.finalUrl}</div>
            </MetricCard>
          </div>

          <div className="grid gap-6 xl:grid-cols-[0.85fr_1.15fr]">
            <div className="rounded-2xl border border-white/[0.08] bg-[#090e16]/90 p-5 sm:p-6">
              <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300">// Primary diagnosis</div>
              <h3 className="mt-3 text-lg font-semibold text-white">{primaryFinding ? primaryFinding.title : "Nenhum achado detectado"}</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">{primaryFinding ? primaryFinding.description : "A análise não identificou problemas entre as verificações executadas. Isso não garante que o site esteja livre de vulnerabilidades."}</p>
              {primaryFinding && <>
                <div className={`mt-4 inline-flex rounded-md border px-2.5 py-1 text-[10px] font-semibold tracking-wider ${getLevelClass(primaryFinding.level)}`}>NÍVEL {LEVEL_LABEL[primaryFinding.level]}</div>
                <div className="mt-5 rounded-xl border border-cyan-300/10 bg-cyan-300/[0.035] p-4"><div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-cyan-200">Ação recomendada</div><p className="mt-2 text-xs leading-6 text-slate-400">{primaryFinding.recommendation}</p></div>
              </>}
              <div className="mt-6 border-t border-white/[0.07] pt-4"><div className="mb-3 text-[10px] uppercase tracking-[0.16em] text-slate-500">Security checks</div>
                {[
                  { label: "HTTPS na URL final", passed: result.results.https.connected },
                  { label: "Certificado TLS validado", passed: tls.valid },
                  { label: "Consulta de cabeçalhos", passed: headerResults.length > 0 },
                ].map((check) => <div key={check.label} className="flex items-center justify-between gap-3 border-b border-white/[0.05] py-3 last:border-0"><span className="text-xs text-slate-400">{check.label}</span><span className={`font-mono text-[10px] ${check.passed ? "text-emerald-300" : "text-orange-300"}`}>{check.passed ? "VERIFICADO" : "ATENÇÃO"}</span></div>)}
              </div>
            </div>

            <div className="rounded-2xl border border-white/[0.08] bg-[#090e16]/90 p-5 sm:p-6">
              <div className="flex flex-wrap items-center justify-between gap-3"><div><div className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300">// Technical details</div><h3 className="mt-2 text-lg font-semibold text-white">Dados da inspeção</h3></div><span className="rounded-md border border-white/10 px-2.5 py-1 font-mono text-[10px] text-slate-500">LIVE REPORT</span></div>
              <div className="mt-5 flex flex-wrap gap-2 border-b border-white/[0.08] pb-4">
                {([["overview", "Visão geral"], ["headers", "Headers"], ["connection", "Conexão TLS"]] as const).map(([tab, label]) => <button key={tab} type="button" onClick={() => setActiveTab(tab)} className={`rounded-lg px-3 py-2 text-xs transition ${activeTab === tab ? "border border-cyan-300/20 bg-cyan-300/[0.08] text-cyan-200" : "border border-transparent text-slate-500 hover:text-slate-200"}`}>{label}</button>)}
              </div>
              {activeTab === "overview" && <div>
                <DetailRow label="URL inicial" value={result.target ?? url} />
                <DetailRow label="URL final" value={result.results.redirects.finalUrl} />
                <DetailRow label="Redirecionamentos" value={String(result.results.redirects.count)} />
                <DetailRow label="Cabeçalhos identificados" value={String(result.results.headers.count)} />
                <DetailRow label="HTTPS na URL final" value={result.results.https.connected ? "Sim" : "Não"} />
                <DetailRow label="Status HTTP" value={String(result.results.https.status ?? "Indisponível")} />
                <DetailRow label="Reputação" value={reputation.safe === true ? "Sem ameaça reportada" : reputation.safe === false ? "Alerta reportado" : "Inconclusiva ou indisponível"} />
              </div>}
              {activeTab === "headers" && <div className="space-y-2 pt-4">
                {headerResults.length === 0 ? <EmptyState message="Nenhum dado de cabeçalho disponível." /> : headerResults.map((header) => <div key={header.name} className="flex flex-col gap-2 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0"><div className="break-all font-mono text-xs text-slate-200">{header.name}</div><div className="mt-1 break-all text-[10px] leading-5 text-slate-500">{header.present ? header.value || "Presente; valor não informado" : "Não identificado"}</div></div>
                  <span className={`shrink-0 self-start rounded-md border px-2 py-1 text-[9px] ${header.present ? "border-emerald-400/20 bg-emerald-400/[0.05] text-emerald-300" : "border-orange-400/20 bg-orange-400/[0.05] text-orange-300"}`}>{header.present ? "PRESENTE" : "AUSENTE"}</span>
                </div>)}
              </div>}
              {activeTab === "connection" && <div className="pt-2">
                <DetailRow label="Certificado validado" value={tls.valid ? "Sim" : "Não confirmado"} />
                <DetailRow label="Emitido para" value={tls.subject || "Não informado"} />
                <DetailRow label="Emissor" value={tls.issuer || "Não informado"} />
                <DetailRow label="Válido desde" value={tls.validFrom || "Não informado"} />
                <DetailRow label="Válido até" value={tls.validTo || "Não informado"} />
                <DetailRow label="Dias restantes" value={tls.daysRemaining == null ? "Não informado" : String(tls.daysRemaining)} />
                <DetailRow label="Detalhe da validação" value={tls.error || "Nenhum erro informado"} />
              </div>}
            </div>
          </div>

          <div className="rounded-2xl border border-white/[0.08] bg-[#090e16]/90 p-5 sm:p-6">
            <div className="flex flex-wrap items-end justify-between gap-3"><div><div className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300">// Findings database</div><h3 className="mt-2 text-lg font-semibold text-white">Achados e recomendações</h3><p className="mt-1 text-xs text-slate-500">Detalhes dos pontos que merecem atenção.</p></div><span className="font-mono text-xs text-slate-500">{String(findings.length).padStart(2, "0")} REGISTRO(S)</span></div>
            {findings.length === 0 ? <div className="mt-5 rounded-xl border border-emerald-400/15 bg-emerald-400/[0.04] p-5"><div className="flex items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-400/20 text-emerald-300">✓</span><div><div className="text-sm font-medium text-emerald-200">Nenhum achado identificado</div><p className="mt-1 text-xs leading-5 text-slate-500">As verificações executadas não retornaram achados classificados. Isso não substitui um teste de segurança completo.</p></div></div></div> : <div className="mt-5 space-y-3">
              {findings.map((finding, index) => {
                const expanded = expandedFinding === finding.id;
                return <div key={finding.id} className="overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.02]">
                  <button type="button" onClick={() => setExpandedFinding(expanded ? null : finding.id)} aria-expanded={expanded} className="flex w-full items-center gap-3 p-4 text-left transition hover:bg-white/[0.025] sm:p-5">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] font-mono text-xs text-slate-500">{String(index + 1).padStart(2, "0")}</span>
                    <span className="min-w-0 flex-1"><span className="block text-sm font-medium text-slate-100">{finding.title}</span><span className="mt-1 block text-xs leading-5 text-slate-500">{finding.description}</span></span>
                    <span className={`shrink-0 rounded-md border px-2 py-1 text-[9px] font-semibold tracking-wider ${getLevelClass(finding.level)}`}>{LEVEL_LABEL[finding.level]}</span>
                    <span className="ml-1 text-sm text-slate-500">{expanded ? "−" : "+"}</span>
                  </button>
                  {expanded && <div className="border-t border-white/[0.07] bg-black/20 px-4 py-4 sm:px-5 sm:pl-[4.25rem]"><div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-cyan-200">Recomendação</div><p className="mt-2 text-xs leading-6 text-slate-400">{finding.recommendation}</p></div>}
                </div>;
              })}
            </div>}
          </div>

          {result.results.redirects.chain.length > 0 && <div className="rounded-2xl border border-white/[0.08] bg-[#090e16]/90 p-5 sm:p-6">
            <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-300">// Navigation trace</div><h3 className="mt-2 text-lg font-semibold text-white">Cadeia de redirecionamentos</h3>
            <div className="mt-5 space-y-3">{result.results.redirects.chain.map((item, index) => <div key={`${item}-${index}`} className="flex min-w-0 items-start gap-3"><div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan-300/20 bg-cyan-300/[0.05] font-mono text-[10px] text-cyan-200">{index + 1}</div><div className="min-w-0 flex-1 break-all rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 font-mono text-xs leading-5 text-slate-400">{item}</div></div>)}</div>
          </div>}

          {result.results.notice && <p className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-[11px] leading-5 text-slate-500"><span className="mr-2 text-cyan-300">i</span>{result.results.notice}</p>}
        </section>}

        <footer className="mt-16 border-t border-white/[0.08] pt-6">
          <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
            <div><div className="font-mono text-xs font-bold tracking-[0.15em] text-slate-400">NEXUS<span className="text-cyan-300">//</span>ZERO <span className="ml-2 font-normal text-slate-600">SECURITY</span></div><p className="mt-2 text-[10px] text-slate-600">Ferramenta de análise técnica de exposição web.</p></div>
            <div className="max-w-lg text-[10px] leading-5 text-slate-600 sm:text-right">Utilize apenas em domínios próprios ou para os quais você tenha autorização. Os resultados são indicativos e não substituem uma auditoria de segurança profissional.</div>
          </div>
        </footer>
      </div>
    </main>
  );
}

function MetricCard({
  label,
  symbol,
  children,
}: {
  label: string;
  symbol: string;
  children: React.ReactNode;
}) {
  return <div className="rounded-2xl border border-white/[0.08] bg-[#0a111a]/90 p-5">
    <div className="flex items-center justify-between"><span className="text-[10px] uppercase tracking-[0.15em] text-slate-500">{label}</span><span className="text-cyan-300">{symbol}</span></div>
    {children}
  </div>;
}

function CountTag({ color, text }: { color: "red" | "orange" | "yellow" | "cyan"; text: string }) {
  const classes = {
    red: "bg-red-500/10 text-red-300",
    orange: "bg-orange-500/10 text-orange-300",
    yellow: "bg-yellow-500/10 text-yellow-200",
    cyan: "bg-cyan-500/10 text-cyan-200",
  };
  return <span className={`rounded-md px-2 py-1 text-[10px] ${classes[color]}`}>{text}</span>;
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return <div className="grid gap-1 border-b border-white/[0.05] py-3 last:border-0 sm:grid-cols-[150px_minmax(0,1fr)] sm:gap-4"><span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span><span className="break-all text-xs leading-5 text-slate-300">{value}</span></div>;
}

function EmptyState({ message }: { message: string }) {
  return <div className="rounded-xl border border-dashed border-white/10 p-6 text-center text-xs text-slate-500">{message}</div>;
}
