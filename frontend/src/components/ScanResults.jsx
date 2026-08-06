import { useEffect, useState } from "react";
import {
  AnimatePresence,
  motion,
} from "framer-motion";

import MarkdownView from "./MarkdownView";
import {
  getFindings,
  getReport,
  reportDownloadUrl,
} from "../services/scanService";

const resultTabs = [
  {
    id: "report",
    label: "Report",
  },
  {
    id: "overview",
    label: "Overview",
  },
  {
    id: "subdomains",
    label: "Subdomains",
  },
  {
    id: "hosts",
    label: "Live hosts",
  },
  {
    id: "endpoints",
    label: "Endpoints",
  },
  {
    id: "ports",
    label: "Ports",
  },
];

// Map the backend severity onto the three visual levels the Overview supports.
function severityToLevel(severity) {
  if (["critical", "high", "medium"].includes(severity)) return "Medium";
  if (severity === "low") return "Review";
  return "Info";
}

// Transform raw whiteboard findings into the shapes the result tables expect.
function buildResultData(findings, target) {
  const subdomains = [];
  const hosts = [];
  const endpoints = [];
  const ports = [];
  const overview = [];

  // The apex domain is always in scope.
  subdomains.push({ name: target, status: "Live", source: "scope" });

  for (const f of findings) {
    switch (f.type) {
      case "subdomain":
        subdomains.push({
          name: f.subdomain,
          status: "Live",
          source: "dns",
        });
        break;
      case "http_response": {
        const powered = f.headers_snapshot?.["X-Powered-By"];
        hosts.push({
          url: f.url,
          status: f.status_code ?? 0,
          title: f.server && f.server !== "not disclosed" ? f.server : "—",
          technology: powered || "—",
        });
        break;
      }
      case "exposed_path":
      case "forbidden_path":
        endpoints.push({
          method: "GET",
          path: f.path,
          host: f.target_domain || target,
          status: f.status_code ?? 0,
        });
        break;
      case "open_port":
        ports.push({
          host: f.target || target,
          port: f.port,
          service: f.service || "unknown",
          version: f.description || "",
        });
        break;
      default:
        break;
    }

    // Surface non-info findings on the Overview panel.
    if (f.severity && f.severity !== "info") {
      overview.push({
        title: f.description || f.type,
        description: `${(f.tool || "scanner").replace(/_/g, " ")} · severity: ${f.severity}`,
        level: severityToLevel(f.severity),
      });
    }
  }

  // Show the most severe findings first, capped so the panel stays readable.
  const order = { Medium: 0, Review: 1, Info: 2 };
  overview.sort((a, b) => order[a.level] - order[b.level]);

  return {
    subdomains,
    hosts,
    endpoints,
    ports,
    findings: overview.slice(0, 24),
  };
}

function formatTime(seconds) {
  const safeSeconds = Math.max(
    0,
    Math.floor(Number(seconds) || 0),
  );

  const minutes = Math.floor(safeSeconds / 60);
  const remainingSeconds = safeSeconds % 60;

  return `${String(minutes).padStart(2, "0")}:${String(
    remainingSeconds,
  ).padStart(2, "0")}`;
}

function getStatusColor(status) {
  if (status >= 200 && status < 300) {
    return "text-[#7ee787]";
  }

  if (status >= 300 && status < 400) {
    return "text-[#8ab4ff]";
  }

  if (status >= 400) {
    return "text-[#ffb86b]";
  }

  return "text-white/40";
}

function ResultHeading({
  eyebrow,
  title,
  description,
}) {
  return (
    <div>
      <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.17em] text-white/25">
        {eyebrow}
      </p>

      <h2 className="mt-2 text-[26px] font-semibold tracking-[-0.8px] text-white">
        {title}
      </h2>

      <p className="mt-2 max-w-[680px] text-[12px] leading-6 text-white/35">
        {description}
      </p>
    </div>
  );
}

function TableHeader({ text }) {
  return (
    <p className="font-['JetBrains_Mono'] text-[8px] uppercase tracking-[0.13em] text-white/25">
      {text}
    </p>
  );
}

function Overview({ resultData }) {
  return (
    <div>
      <ResultHeading
        eyebrow="Overview"
        title="Attack surface summary"
        description="The most relevant assets and services discovered during this reconnaissance scan."
      />

      <div className="mt-8 grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(260px,0.8fr)]">
        <div className="overflow-hidden rounded-[13px] border border-white/[0.08] bg-white/[0.02]">
          <div className="border-b border-white/[0.07] px-5 py-4">
            <p className="text-[13px] font-semibold text-white/70">
              Interesting findings
            </p>
          </div>

          {resultData.findings.length === 0 && (
            <div className="px-5 py-6 text-[12px] text-white/35">
              No elevated-severity findings were recorded. See the full report
              for details.
            </div>
          )}

          {resultData.findings.map((finding, index) => (
            <div
              key={`${finding.title}-${index}`}
              className="flex flex-col gap-3 border-b border-white/[0.055] px-5 py-5 last:border-b-0 sm:flex-row sm:items-start sm:justify-between"
            >
              <div>
                <p className="text-[13px] font-medium text-white/70">
                  {finding.title}
                </p>

                <p className="mt-2 text-[11px] leading-5 text-white/30">
                  {finding.description}
                </p>
              </div>

              <span
                className={`
                  w-fit shrink-0 rounded-full
                  px-3 py-1
                  font-['JetBrains_Mono']
                  text-[8px] uppercase
                  tracking-[0.1em]
                  ${
                    finding.level === "Medium"
                      ? "bg-[#ffb86b]/10 text-[#ffb86b]"
                      : finding.level === "Review"
                        ? "bg-[#8ab4ff]/10 text-[#8ab4ff]"
                        : "bg-white/[0.05] text-white/40"
                  }
                `}
              >
                {finding.level}
              </span>
            </div>
          ))}
        </div>

        <div className="rounded-[13px] border border-white/[0.08] bg-white/[0.02] p-5">
          <p className="text-[13px] font-semibold text-white/70">
            Detected services
          </p>

          <div className="mt-5 space-y-4">
            {resultData.ports.map((item) => (
              <div
                key={`${item.host}-${item.port}`}
                className="flex items-center justify-between gap-4"
              >
                <div className="min-w-0">
                  <p className="truncate font-['JetBrains_Mono'] text-[10px] text-white/55">
                    {item.host}
                  </p>

                  <p className="mt-1 text-[9px] text-white/25">
                    {item.version}
                  </p>
                </div>

                <div className="shrink-0 text-right">
                  <p className="font-['JetBrains_Mono'] text-[11px] text-[#8ab4ff]">
                    {item.port}
                  </p>

                  <p className="mt-1 text-[8px] uppercase text-white/25">
                    {item.service}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function SubdomainResults({ data }) {
  return (
    <div>
      <ResultHeading
        eyebrow="Assets"
        title="Discovered subdomains"
        description="Subdomains collected from passive reconnaissance sources."
      />

      <div className="mt-8 overflow-hidden rounded-[13px] border border-white/[0.08]">
        <div className="hidden grid-cols-[minmax(220px,1fr)_120px_140px] border-b border-white/[0.07] bg-white/[0.025] px-5 py-3 md:grid">
          <TableHeader text="Hostname" />
          <TableHeader text="Status" />
          <TableHeader text="Source" />
        </div>

        {data.map((item) => (
          <div
            key={item.name}
            className="grid gap-3 border-b border-white/[0.055] px-5 py-4 last:border-b-0 md:grid-cols-[minmax(220px,1fr)_120px_140px] md:items-center md:gap-0"
          >
            <p className="break-all font-['JetBrains_Mono'] text-[11px] text-white/65">
              {item.name}
            </p>

            <span
              className={`w-fit rounded-full px-3 py-1 font-['JetBrains_Mono'] text-[8px] uppercase tracking-[0.1em] ${
                item.status === "Live"
                  ? "bg-[#7ee787]/10 text-[#7ee787]"
                  : "bg-white/[0.05] text-white/30"
              }`}
            >
              {item.status}
            </span>

            <p className="font-['JetBrains_Mono'] text-[10px] text-white/30">
              {item.source}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function HostResults({ data }) {
  return (
    <div>
      <ResultHeading
        eyebrow="HTTPX"
        title="Responsive hosts"
        description="Hosts that returned a valid response during HTTP probing."
      />

      <div className="mt-8 overflow-hidden rounded-[13px] border border-white/[0.08]">
        <div className="hidden grid-cols-[minmax(240px,1.2fr)_90px_minmax(150px,1fr)_130px] border-b border-white/[0.07] bg-white/[0.025] px-5 py-3 md:grid">
          <TableHeader text="Host" />
          <TableHeader text="Status" />
          <TableHeader text="Title" />
          <TableHeader text="Technology" />
        </div>

        {data.map((item) => (
          <div
            key={item.url}
            className="grid gap-3 border-b border-white/[0.055] px-5 py-4 last:border-b-0 md:grid-cols-[minmax(240px,1.2fr)_90px_minmax(150px,1fr)_130px] md:items-center md:gap-0"
          >
            <p className="break-all font-['JetBrains_Mono'] text-[10px] text-white/65">
              {item.url}
            </p>

            <p
              className={`font-['JetBrains_Mono'] text-[10px] ${getStatusColor(
                item.status,
              )}`}
            >
              {item.status}
            </p>

            <p className="text-[11px] text-white/40">
              {item.title}
            </p>

            <p className="font-['JetBrains_Mono'] text-[9px] text-white/30">
              {item.technology}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function EndpointResults({ data }) {
  return (
    <div>
      <ResultHeading
        eyebrow="Crawler"
        title="Collected endpoints"
        description="Application routes and API endpoints discovered by the crawler."
      />

      <div className="mt-8 overflow-hidden rounded-[13px] border border-white/[0.08]">
        <div className="hidden grid-cols-[80px_minmax(220px,1fr)_minmax(180px,1fr)_80px] border-b border-white/[0.07] bg-white/[0.025] px-5 py-3 md:grid">
          <TableHeader text="Method" />
          <TableHeader text="Endpoint" />
          <TableHeader text="Host" />
          <TableHeader text="Status" />
        </div>

        {data.map((item, index) => (
          <div
            key={`${item.host}-${item.path}-${index}`}
            className="grid gap-3 border-b border-white/[0.055] px-5 py-4 last:border-b-0 md:grid-cols-[80px_minmax(220px,1fr)_minmax(180px,1fr)_80px] md:items-center md:gap-0"
          >
            <span className="w-fit rounded-[5px] bg-[#8ab4ff]/10 px-2 py-1 font-['JetBrains_Mono'] text-[8px] text-[#8ab4ff]">
              {item.method}
            </span>

            <p className="break-all font-['JetBrains_Mono'] text-[10px] text-white/65">
              {item.path}
            </p>

            <p className="break-all font-['JetBrains_Mono'] text-[9px] text-white/30">
              {item.host}
            </p>

            <p
              className={`font-['JetBrains_Mono'] text-[10px] ${getStatusColor(
                item.status,
              )}`}
            >
              {item.status}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function PortResults({ data }) {
  return (
    <div>
      <ResultHeading
        eyebrow="Nmap"
        title="Ports and services"
        description="Network services detected during the service scanning stage."
      />

      <div className="mt-8 overflow-hidden rounded-[13px] border border-white/[0.08]">
        <div className="hidden grid-cols-[180px_80px_120px_minmax(220px,1fr)] border-b border-white/[0.07] bg-white/[0.025] px-5 py-3 md:grid">
          <TableHeader text="Host" />
          <TableHeader text="Port" />
          <TableHeader text="Service" />
          <TableHeader text="Version" />
        </div>

        {data.map((item) => (
          <div
            key={`${item.host}-${item.port}`}
            className="grid gap-3 border-b border-white/[0.055] px-5 py-4 last:border-b-0 md:grid-cols-[180px_80px_120px_minmax(220px,1fr)] md:items-center md:gap-0"
          >
            <p className="font-['JetBrains_Mono'] text-[10px] text-white/40">
              {item.host}
            </p>

            <p className="font-['JetBrains_Mono'] text-[10px] text-[#8ab4ff]">
              {item.port}
            </p>

            <p className="text-[10px] text-white/50">
              {item.service}
            </p>

            <p className="text-[10px] text-white/30">
              {item.version}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportPanel({ loading, error, markdown, downloadHref, target }) {
  return (
    <div>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <ResultHeading
          eyebrow="Report"
          title="Assessment report"
          description="The final security assessment generated by the reporting agent. Read it below or download the raw markdown."
        />

        <a
          href={loading || error ? undefined : downloadHref}
          download={`maximrecon_${(target || "target").replace(/\./g, "_")}_report.md`}
          aria-disabled={loading || error || !downloadHref}
          onClick={(event) => {
            if (loading || error || !downloadHref) event.preventDefault();
          }}
          className={`
            inline-flex shrink-0 items-center gap-2
            rounded-full px-5 py-3 text-[12px] font-bold
            transition
            ${
              loading || error || !downloadHref
                ? "cursor-not-allowed bg-white/10 text-white/30"
                : "bg-white text-[#181468] hover:bg-white/90"
            }
          `}
        >
          ↓ Download .md
        </a>
      </div>

      <div className="mt-8 rounded-[13px] border border-white/[0.08] bg-[rgba(3,5,12,0.55)] p-6 md:p-8">
        {loading && (
          <p className="font-['JetBrains_Mono'] text-[12px] text-white/40">
            Loading report…
          </p>
        )}

        {!loading && error && (
          <p className="font-['JetBrains_Mono'] text-[12px] text-[#ffb86b]">
            {error}
          </p>
        )}

        {!loading && !error && markdown && (
          <MarkdownView markdown={markdown} />
        )}
      </div>
    </div>
  );
}

function ScanResults({
  target,
  engagementId,
  scanResult,
  summary,
  elapsedSeconds,
  showTerminal,
  onToggleTerminal,
  onNewScan,
}) {
  const [activeResultTab, setActiveResultTab] =
    useState("report");

  const [findings, setFindings] = useState([]);
  const [reportMarkdown, setReportMarkdown] = useState(null);
  const [reportError, setReportError] = useState(null);
  const [reportLoading, setReportLoading] = useState(true);

  // Once the scan completes, pull the structured findings + markdown report.
  useEffect(() => {
    if (!engagementId) return;

    let cancelled = false;

    getFindings(engagementId)
      .then((data) => {
        if (!cancelled) setFindings(data.findings || []);
      })
      .catch(() => {
        /* non-fatal — the report is the primary artifact */
      });

    setReportLoading(true);
    getReport(engagementId)
      .then((data) => {
        if (cancelled) return;
        setReportMarkdown(data.report_markdown);
        setReportError(null);
      })
      .catch((error) => {
        if (cancelled) return;
        setReportError(
          error?.message || "Report is not available yet.",
        );
      })
      .finally(() => {
        if (!cancelled) setReportLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [engagementId]);

  const resolvedSummary =
    summary ??
    scanResult?.summary ?? {
      subdomains: 0,
      liveHosts: 0,
      urls: 0,
      openPorts: 0,
    };

  const resultData = buildResultData(findings, target);

  const downloadHref = engagementId
    ? reportDownloadUrl(engagementId)
    : null;

  return (
    <motion.main
      initial={{
        opacity: 0,
        y: 35,
      }}
      animate={{
        opacity: 1,
        y: 0,
      }}
      transition={{
        duration: 0.7,
        ease: [0.22, 1, 0.36, 1],
      }}
      className="
        mx-auto w-full max-w-[1450px]
        px-6 pb-28 pt-3
        lg:px-10 xl:px-12
      "
    >
      {/* Completion banner */}
      <section
        className="
          relative overflow-hidden
          rounded-[16px]
          border border-[#7ee787]/15
          bg-[rgba(5,10,17,0.8)]
          p-6
          shadow-[0_30px_90px_rgba(0,0,0,0.3)]
          backdrop-blur-[20px]
          md:p-8
        "
      >
        <div className="pointer-events-none absolute right-[-100px] top-[-130px] h-[340px] w-[340px] rounded-full bg-[#7ee787]/[0.055] blur-[90px]" />

        <div className="relative flex flex-col gap-7 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full border border-[#7ee787]/20 bg-[#7ee787]/10 text-[#7ee787]">
                ✓
              </div>

              <div>
                <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.17em] text-[#7ee787]/70">
                  Reconnaissance complete
                </p>

                <h1 className="mt-1 break-all text-[27px] font-semibold tracking-[-1px] text-white md:text-[34px]">
                  {target}
                </h1>
              </div>
            </div>

            <p className="mt-5 max-w-[670px] text-[13px] leading-6 text-white/40">
              The reconnaissance pipeline completed
              successfully. Review the discovered
              assets, responsive hosts, endpoints and
              exposed services below.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={onToggleTerminal}
              className="
                rounded-full border border-white/10
                bg-white/[0.04] px-5 py-3
                text-[12px] font-semibold text-white/60
                transition
                hover:border-white/20
                hover:bg-white/[0.07]
                hover:text-white
              "
            >
              {showTerminal
                ? "Hide terminal"
                : "View terminal"}
            </button>

            <button
              type="button"
              onClick={onNewScan}
              className="
                rounded-full bg-white px-5 py-3
                text-[12px] font-bold text-[#181468]
                transition hover:bg-white/90
              "
            >
              New scan
            </button>
          </div>
        </div>

        <div className="relative mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-[11px] border border-white/[0.07] bg-white/[0.07] md:grid-cols-4">
          {[
            [
              "Duration",
              formatTime(elapsedSeconds),
            ],
            ["Status", "Completed"],
            ["Stages", "6/6"],
            ["Exit code", "0"],
          ].map(([label, value]) => (
            <div
              key={label}
              className="bg-[#080b16]/95 px-5 py-4"
            >
              <p className="font-['JetBrains_Mono'] text-[8px] uppercase tracking-[0.14em] text-white/25">
                {label}
              </p>

              <p className="mt-2 font-['JetBrains_Mono'] text-[11px] text-white/70">
                {value}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Summary strip */}
      <section className="mt-6 border-y border-white/[0.08] bg-white/[0.018] backdrop-blur-[14px]">
        <div className="grid grid-cols-2 md:grid-cols-4">
          {[
            [
              resolvedSummary.subdomains,
              "Subdomains",
            ],
            [
              resolvedSummary.liveHosts,
              "Live hosts",
            ],
            [
              resolvedSummary.urls,
              "Endpoints",
            ],
            [
              resolvedSummary.openPorts,
              "Open ports",
            ],
          ].map(([value, label], index) => (
            <motion.div
              key={label}
              initial={{
                opacity: 0,
                y: 15,
              }}
              animate={{
                opacity: 1,
                y: 0,
              }}
              transition={{
                duration: 0.4,
                delay: index * 0.07,
              }}
              className="relative px-6 py-6"
            >
              {index !== 3 && (
                <div className="absolute right-0 top-[25%] hidden h-1/2 w-px bg-white/[0.07] md:block" />
              )}

              <p className="text-[31px] font-semibold tracking-[-1.3px] text-white">
                {value}
              </p>

              <p className="mt-2 font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.14em] text-white/30">
                {label}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Results dashboard */}
      <section
        className="
          mt-6 overflow-hidden rounded-[16px]
          border border-white/[0.08]
          bg-[rgba(5,7,17,0.72)]
          shadow-[0_28px_90px_rgba(0,0,0,0.25)]
          backdrop-blur-[18px]
        "
      >
        <div className="grid min-h-[560px] lg:grid-cols-[210px_minmax(0,1fr)]">
          <aside className="border-b border-white/[0.07] p-4 lg:border-b-0 lg:border-r">
            <p className="px-3 pb-4 pt-2 font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.17em] text-white/25">
              Scan report
            </p>

            <nav className="flex gap-2 overflow-x-auto lg:flex-col">
              {resultTabs.map((tab) => {
                const isActive =
                  activeResultTab === tab.id;

                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() =>
                      setActiveResultTab(tab.id)
                    }
                    className={`
                      flex shrink-0 items-center
                      justify-between rounded-[9px]
                      px-3 py-3 text-left
                      text-[12px] transition
                      lg:w-full
                      ${
                        isActive
                          ? "bg-white/[0.075] text-white"
                          : "text-white/35 hover:bg-white/[0.035] hover:text-white/65"
                      }
                    `}
                  >
                    {tab.label}

                    {isActive && (
                      <span className="ml-5 h-1.5 w-1.5 rounded-full bg-[#8ab4ff]" />
                    )}
                  </button>
                );
              })}
            </nav>
          </aside>

          <div className="min-w-0 p-5 md:p-7">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeResultTab}
                initial={{
                  opacity: 0,
                  y: 10,
                }}
                animate={{
                  opacity: 1,
                  y: 0,
                }}
                exit={{
                  opacity: 0,
                  y: -8,
                }}
                transition={{
                  duration: 0.25,
                }}
              >
                {activeResultTab ===
                  "report" && (
                  <ReportPanel
                    loading={reportLoading}
                    error={reportError}
                    markdown={reportMarkdown}
                    downloadHref={downloadHref}
                    target={target}
                  />
                )}

                {activeResultTab ===
                  "overview" && (
                  <Overview
                    resultData={resultData}
                  />
                )}

                {activeResultTab ===
                  "subdomains" && (
                  <SubdomainResults
                    data={
                      resultData.subdomains
                    }
                  />
                )}

                {activeResultTab ===
                  "hosts" && (
                  <HostResults
                    data={resultData.hosts}
                  />
                )}

                {activeResultTab ===
                  "endpoints" && (
                  <EndpointResults
                    data={
                      resultData.endpoints
                    }
                  />
                )}

                {activeResultTab ===
                  "ports" && (
                  <PortResults
                    data={resultData.ports}
                  />
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </section>
    </motion.main>
  );
}

export default ScanResults;