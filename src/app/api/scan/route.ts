
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import tls from "node:tls";
import { NextResponse } from "next/server";

export const runtime = "nodejs";

type HeaderResult = {
  name: string;
  present: boolean;
  value: string | null;
};

type ReputationResult = {
  status: "not_configured" | "clean" | "flagged" | "error";
  provider: string;
  checkedUrls: string[];
  threats: string[];
  matches: string[];
  safe?: boolean;
  checked: boolean;
  error: string | null;
  message: string;
};

type TlsResult = {
  valid: boolean;
  subject: string;
  issuer: string;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  error: string | null;
};

type PublicResponse = {
  status: number;
  headers: Record<string, string | string[] | undefined>;
};

type Address = {
  address: string;
  family: number;
};

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
];

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 10000;

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(
      (part) =>
        !Number.isInteger(part) || part < 0 || part > 255,
    )
  ) {
    return true;
  }

  const [a, b, c] = parts;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

function expandIPv6(ip: string): number[] | null {
  let value = ip.toLowerCase().split("%")[0];

  if (!value || isIP(value) !== 6) return null;

  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = value.slice(lastColon + 1);

    if (isIP(ipv4) !== 4) return null;

    const octets = ipv4.split(".").map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);

    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }

  const halves = value.split("::");
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right =
    halves.length === 2 && halves[1]
      ? halves[1].split(":").filter(Boolean)
      : [];

  const missing = 8 - left.length - right.length;

  if (
    (halves.length === 1 && missing !== 0) ||
    (halves.length === 2 && missing < 1)
  ) {
    return null;
  }

  const groups = [
    ...left,
    ...Array(halves.length === 2 ? missing : 0).fill("0"),
    ...right,
  ].map((group) => parseInt(group, 16));

  if (
    groups.length !== 8 ||
    groups.some(
      (group) =>
        !Number.isInteger(group) || group < 0 || group > 65535,
    )
  ) {
    return null;
  }

  return groups;
}

function isPrivateIPv6(ip: string): boolean {
  const groups = expandIPv6(ip);
  if (!groups) return true;

  const allZero = groups.every((group) => group === 0);
  const loopback =
    groups.slice(0, 7).every((group) => group === 0) &&
    groups[7] === 1;

  if (allZero || loopback) return true;

  // IPv4 mapeado em IPv6.
  if (
    groups.slice(0, 5).every((group) => group === 0) &&
    groups[5] === 0xffff
  ) {
    const ipv4 = [
      groups[6] >> 8,
      groups[6] & 255,
      groups[7] >> 8,
      groups[7] & 255,
    ].join(".");

    return isPrivateIPv4(ipv4);
  }

  // Aceita apenas o espaço global de unicast 2000::/3.
  const first = groups[0];
  if (first < 0x2000 || first > 0x3fff) return true;

  // Blocos especiais, de documentação e de transição.
  if (
    (first === 0x2001 && groups[1] <= 0x01ff) ||
    (first === 0x2001 && groups[1] === 0x0db8) ||
    first === 0x2002 ||
    (first === 0x3fff && groups[1] <= 0x0fff)
  ) {
    return true;
  }

  return false;
}

function isPrivateIP(ip: string): boolean {
  const version = isIP(ip);

  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);

  return true;
}

function normalizeHostname(url: URL): string {
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
}

async function validatePublicTarget(url: URL): Promise<Address[]> {
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Somente URLs HTTP e HTTPS são permitidas.");
  }

  if (url.username || url.password) {
    throw new Error("URLs com credenciais não são permitidas.");
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("Somente as portas 80 e 443 são permitidas.");
  }

  // Evita consultar uma porta diferente daquela validada pelo scanner.
  if (
    (url.protocol === "https:" && url.port === "80") ||
    (url.protocol === "http:" && url.port === "443")
  ) {
    throw new Error("A porta informada não corresponde ao protocolo da URL.");
  }

  const hostname = normalizeHostname(url);

  const blockedSuffixes = [
    ".localhost",
    ".local",
    ".internal",
    ".home",
    ".lan",
    ".test",
    ".invalid",
    ".example",
    ".onion",
  ];

  if (
    !hostname ||
    hostname === "localhost" ||
    blockedSuffixes.some((suffix) => hostname.endsWith(suffix))
  ) {
    throw new Error("Domínios locais ou reservados não são permitidos.");
  }

  if (isIP(hostname)) {
    if (isPrivateIP(hostname)) {
      throw new Error(
        "Endereços IP privados ou reservados não são permitidos.",
      );
    }

    return [{ address: hostname, family: isIP(hostname) }];
  }

  if (!hostname.includes(".")) {
    throw new Error("Informe um domínio público válido.");
  }

  let records: Address[];

  try {
    records = await dnsLookup(hostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new Error("Não foi possível resolver o domínio informado.");
  }

  if (
    records.length === 0 ||
    records.some((record) => isPrivateIP(record.address))
  ) {
    throw new Error(
      "O domínio aponta para um endereço privado ou não permitido.",
    );
  }

  return records;
}

function getDomainInput(value: unknown): URL {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("Informe um domínio para analisar.");
  }

  let raw = value.trim();

  if (!/^https?:\/\//i.test(raw)) {
    raw = `https://${raw}`;
  }

  let url: URL;

  try {
    url = new URL(raw);
  } catch {
    throw new Error("O domínio ou a URL informada é inválida.");
  }

  url.hash = "";
  return url;
}

/**
 * Faz a requisição apenas para endereços previamente validados.
 * Não segue redirecionamentos automaticamente nem baixa o corpo completo.
 */
async function requestPublicUrl(
  url: URL,
  addresses: Address[],
): Promise<PublicResponse> {
  return new Promise((resolve, reject) => {
    const hostname = normalizeHostname(url);
    const selectedAddresses = addresses.filter(
      (item) => !isPrivateIP(item.address),
    );

    if (selectedAddresses.length === 0) {
      reject(new Error("Nenhum endereço público validado disponível."));
      return;
    }

    const pinnedLookup = ((
      _requestedHostname: string,
      options: { all?: boolean },
      callback: (
        error: NodeJS.ErrnoException | null,
        address: string | Address[],
        family?: number,
      ) => void,
    ) => {
      if (options?.all) {
        callback(null, selectedAddresses);
      } else {
        const selected = selectedAddresses[0];
        callback(null, selected.address, selected.family);
      }
    }) as never;

    const onResponse = (
      response: import("node:http").IncomingMessage,
    ) => {
      const headers: Record<
        string,
        string | string[] | undefined
      > = {};

      for (const [name, value] of Object.entries(response.headers)) {
        headers[name] = value;
      }

      const status = response.statusCode ?? 0;

      // Apenas status e cabeçalhos são necessários para esta análise.
      response.destroy();
      resolve({ status, headers });
    };

    const commonOptions = {
      method: "GET" as const,
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        "User-Agent": "NEXUS-ZERO-Security-Scanner/0.8",
        Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
        Connection: "close",
      },
      lookup: pinnedLookup,
    };

    const req =
      url.protocol === "https:"
        ? httpsRequest(
            url,
            {
              ...commonOptions,
              // A inspeção do certificado é feita separadamente por getTlsInfo.
              rejectUnauthorized: false,
              servername: isIP(hostname) ? undefined : hostname,
            },
            onResponse,
          )
        : httpRequest(url, commonOptions, onResponse);

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error("Tempo limite ao consultar o domínio."));
    });

    req.once("error", (error) => reject(error));
    req.end();
  });
}

function emptyTls(error: string): TlsResult {
  return {
    valid: false,
    subject: "Indisponível",
    issuer: "Indisponível",
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    error,
  };
}

async function getTlsInfo(
  hostname: string,
  addresses: Address[],
): Promise<TlsResult> {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const address = addresses.find(
    (item) => !isPrivateIP(item.address),
  );

  if (!address) {
    return emptyTls(
      "Não há endereço público validado para a consulta TLS.",
    );
  }

  return new Promise((resolve) => {
    const socket = tls.connect({
      host: address.address,
      port: 443,
      servername: isIP(normalized) ? undefined : normalized,
      rejectUnauthorized: false,
      timeout: REQUEST_TIMEOUT_MS,
    });

    let finished = false;

    const finish = (result: TlsResult) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
      finish(emptyTls("Tempo limite ao consultar o certificado TLS."));
    });

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const now = Date.now();

      const validToDate = cert.valid_to
        ? new Date(cert.valid_to)
        : null;

      const validFromDate = cert.valid_from
        ? new Date(cert.valid_from)
        : null;

      const daysRemaining = validToDate
        ? Math.floor(
            (validToDate.getTime() - now) / 86400000,
          )
        : null;

      const datesValid =
        validFromDate !== null &&
        validToDate !== null &&
        now >= validFromDate.getTime() &&
        now <= validToDate.getTime();

      let identityError: Error | undefined;

      try {
        identityError = tls.checkServerIdentity(normalized, cert);
      } catch {
        identityError = new Error(
          "Não foi possível validar o hostname.",
        );
      }

      const valid =
        socket.authorized === true &&
        datesValid &&
        !identityError;

      finish({
        valid,
        subject:
          typeof cert.subject?.CN === "string"
            ? cert.subject.CN
            : "Não informado",
        issuer:
          typeof cert.issuer?.O === "string"
            ? cert.issuer.O
            : typeof cert.issuer?.CN === "string"
              ? cert.issuer.CN
              : "Não informado",
        validFrom: cert.valid_from ?? null,
        validTo: cert.valid_to ?? null,
        daysRemaining,
        error: valid
          ? null
          : identityError?.message ??
            (socket.authorizationError
              ? String(socket.authorizationError)
              : "O certificado não passou em todas as verificações."),
      });
    });

    socket.once("error", (error) => {
      finish(emptyTls(error.message));
    });
  });
}

async function checkReputation(
  urls: string[],
): Promise<ReputationResult> {
  const provider = "Google Safe Browsing";
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      status: "not_configured",
      provider,
      checkedUrls: urls,
      threats: [],
      matches: [],
      checked: false,
      error: "A chave da API não está configurada no servidor.",
      message: "A chave da API não está configurada no servidor.",
    };
  }

  try {
    const endpoint = new URL(
      "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    );

    endpoint.searchParams.set("key", apiKey);

    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "nexus-zero-security",
          clientVersion: "0.8.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: urls.map((url) => ({ url })),
        },
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      cache: "no-store",
    });

    if (!response.ok) {
      const message =
        `O serviço de reputação respondeu com HTTP ${response.status}.`;

      return {
        status: "error",
        provider,
        checkedUrls: urls,
        threats: [],
        matches: [],
        checked: false,
        error: message,
        message,
      };
    }

    const data = (await response.json()) as {
      matches?: Array<{
        threatType?: string;
        threat?: { url?: string };
      }>;
    };

    const matches = data.matches ?? [];
    const threats = matches.map(
      (match) =>
        `${match.threatType ?? "AMEAÇA"}${
          match.threat?.url ? ` — ${match.threat.url}` : ""
        }`,
    );

    if (matches.length > 0) {
      return {
        status: "flagged",
        provider,
        checkedUrls: urls,
        threats,
        matches: threats,
        safe: false,
        checked: true,
        error: null,
        message:
          "O serviço identificou correspondências com ameaças conhecidas.",
      };
    }

    return {
      status: "clean",
      provider,
      checkedUrls: urls,
      threats: [],
      matches: [],
      safe: true,
      checked: true,
      error: null,
      message:
        "Nenhuma correspondência de ameaça foi encontrada nas URLs consultadas.",
    };
  } catch {
    const message = "Não foi possível concluir a consulta de reputação.";

    return {
      status: "error",
      provider,
      checkedUrls: urls,
      threats: [],
      matches: [],
      checked: false,
      error: message,
      message,
    };
  }
}

function getHeaderValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | null {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) return value.join(", ");
  return typeof value === "string" ? value : null;
}

export async function POST(request: Request) {
  try {
    let body: { url?: unknown; domain?: unknown };

    try {
      body = (await request.json()) as {
        url?: unknown;
        domain?: unknown;
      };
    } catch {
      return NextResponse.json(
        { success: false, error: "O corpo da requisição precisa ser um JSON válido." },
        { status: 400 },
      );
    }

    // Aceita "url" do frontend e "domain" para compatibilidade.
    const initialUrl = getDomainInput(body.url ?? body.domain);
    let currentUrl = new URL(initialUrl.toString());

    let currentAddresses = await validatePublicTarget(currentUrl);

    const redirectChain: Array<{
      status: number;
      url: string;
      location: string;
    }> = [];

    let response: PublicResponse | null = null;

    for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt++) {
      currentAddresses = await validatePublicTarget(currentUrl);
      response = await requestPublicUrl(currentUrl, currentAddresses);

      const location = getHeaderValue(response.headers, "location");

      if (
        response.status >= 300 &&
        response.status < 400 &&
        location
      ) {
        if (attempt === MAX_REDIRECTS) {
          throw new Error(
            "O domínio excedeu o limite de redirecionamentos.",
          );
        }

        const nextUrl = new URL(location, currentUrl);
        nextUrl.hash = "";

        // Valida o destino antes de fazer a próxima requisição.
        await validatePublicTarget(nextUrl);

        redirectChain.push({
          status: response.status,
          url: currentUrl.toString(),
          location: nextUrl.toString(),
        });

        currentUrl = nextUrl;
        continue;
      }

      break;
    }

    if (!response) {
      throw new Error("Não foi possível obter uma resposta do domínio.");
    }

    const headerResults: HeaderResult[] = SECURITY_HEADERS.map((name) => {
      const value = getHeaderValue(response!.headers, name);

      return {
        name,
        present: value !== null && value.trim().length > 0,
        value,
      };
    });

    const tlsInfo =
      currentUrl.protocol === "https:"
        ? await getTlsInfo(
            normalizeHostname(currentUrl),
            currentAddresses,
          )
        : emptyTls(
            "O destino final utiliza HTTP. A validação do certificado exige HTTPS.",
          );

    const urlsToCheck = [
      initialUrl.toString(),
      currentUrl.toString(),
    ].filter((value, index, list) => list.indexOf(value) === index);

    const reputation = await checkReputation(urlsToCheck);

    const headersPresent = headerResults.filter(
      (header) => header.present,
    ).length;

    // Lista de URLs em ordem de navegação para a interface.
    const chain =
      redirectChain.length > 0
        ? [
            redirectChain[0].url,
            ...redirectChain.map((item) => item.location),
          ]
        : [];

    return NextResponse.json({
      success: true,
      target: initialUrl.toString(),
      domain: normalizeHostname(initialUrl),
      scannedAt: new Date().toISOString(),
      results: {
        https: {
          status: response.status,
          connected: currentUrl.protocol === "https:",
        },
        headers: {
          count: headersPresent,
          present: headersPresent,
          total: headerResults.length,
          results: headerResults,
        },
        redirects: {
          count: redirectChain.length,
          finalUrl: currentUrl.toString(),
          chain,
        },
        tls: tlsInfo,
        reputation: {
          ...reputation,
          safe:
            reputation.status === "clean"
              ? true
              : reputation.status === "flagged"
                ? false
                : undefined,
          checked:
            reputation.status === "clean" ||
            reputation.status === "flagged",
          matches: reputation.matches ?? reputation.threats,
          error:
            reputation.status === "error" ||
            reputation.status === "not_configured"
              ? reputation.message
              : null,
        },
        notice:
          "Análise automatizada e limitada aos testes exibidos. Um resultado sem correspondências não garante que o domínio seja seguro.",
      },
    });
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Ocorreu um erro inesperado durante a análise.";

    return NextResponse.json(
      { success: false, error: message },
      { status: 400 },
    );
  }
}
