import { useEffect, useRef, useState } from "react";
import { openLiveSocket } from "../services/scanService";

const previewSteps = [
  {
    text: "❯ reconforge scan example.com --full",
    className: "command",
  },
  {
    text: "",
    className: "dim",
  },
  {
    text: "⠹ Validating target...",
    className: "info",
  },
  {
    text: "[SUCCESS] Target is valid",
    className: "success",
  },
  {
    text: "$ subfinder -d example.com -silent",
    className: "command",
  },
  {
    text: "api.example.com",
    className: "dim",
  },
  {
    text: "cdn.example.com",
    className: "dim",
  },
  {
    text: "mail.example.com",
    className: "dim",
  },
  {
    text: "[SUCCESS] 128 unique subdomains collected",
    className: "success",
  },
];

// Colour a streamed log line by its severity marker / level.
function classForLog(line, level) {
  if (/^\[SUCCESS\]/i.test(line)) return "success";
  if (/^\[ERROR\]/i.test(line) || level === "ERROR") return "error";
  if (/^\[WARNING\]/i.test(line) || level === "WARNING") return "warning";
  if (/^\[/.test(line)) return "info";
  return "dim";
}

function Terminal({
  mode = "preview",
  target = "example.com",
  engagementId = null,
  onComplete,
  onProgress,
  onStageChange,
  onCounts,
  onError,
}) {
  const [lines, setLines] = useState([]);
  const [activeCommandId, setActiveCommandId] = useState(null);

  const terminalBodyRef = useRef(null);
  const lineRefs = useRef({});

  // --- Preview mode: looping fake terminal shown on the landing page ---
  useEffect(() => {
    if (mode !== "preview") return undefined;

    let cancelled = false;
    let timeoutId;
    let currentIndex = 0;

    setLines([]);
    setActiveCommandId(null);
    lineRefs.current = {};

    const addLine = (text, className = "dim") => {
      if (cancelled) return null;
      const id = crypto.randomUUID();
      setLines((current) => [...current, { id, text, className }]);
      return id;
    };

    const showNextLine = () => {
      if (cancelled) return;

      if (currentIndex >= previewSteps.length) {
        timeoutId = setTimeout(() => {
          if (cancelled) return;
          setLines([]);
          setActiveCommandId(null);
          lineRefs.current = {};
          currentIndex = 0;
          showNextLine();
        }, 1800);
        return;
      }

      const step = previewSteps[currentIndex];
      const lineId = addLine(step.text, step.className);
      if (step.className === "command") {
        setActiveCommandId(lineId);
      }
      currentIndex += 1;
      timeoutId = setTimeout(showNextLine, 450);
    };

    showNextLine();

    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
    };
  }, [mode]);

  // --- Scanning mode: live event stream from the backend over WebSocket ---
  useEffect(() => {
    if (mode !== "scanning" || !engagementId) return undefined;

    let cancelled = false;

    setLines([]);
    setActiveCommandId(null);
    lineRefs.current = {};

    const addLine = (text, className = "dim") => {
      if (cancelled) return null;
      const id = crypto.randomUUID();
      setLines((current) => [...current, { id, text, className }]);
      return id;
    };

    const initialCommandId = addLine(
      `❯ reconforge scan ${target} --full`,
      "command",
    );
    setActiveCommandId(initialCommandId);
    addLine("", "dim");
    addLine("[INFO] Connecting to assessment engine...", "info");

    const socket = openLiveSocket(engagementId);

    socket.onmessage = (message) => {
      if (cancelled) return;

      let event;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }

      switch (event.type) {
        case "started":
          addLine(`[INFO] Engagement live for ${event.target}`, "info");
          addLine("", "dim");
          break;

        case "log":
          addLine(event.line, classForLog(event.line, event.level));
          break;

        case "phase": {
          onStageChange?.({
            id: event.stageId,
            label: event.label,
            status: "running",
            completedStages: event.completedStages,
          });
          onProgress?.({
            progress: event.progress,
            stageId: event.stageId,
            stageLabel: event.label,
            completedStages: event.completedStages,
          });
          // Structured phase marker (also anchors terminal auto-scroll).
          const phaseCommandId = addLine(`— ${event.label}`, "command");
          setActiveCommandId(phaseCommandId);
          break;
        }

        case "counts":
          onCounts?.(event.summary);
          break;

        case "complete":
          addLine("", "dim");
          addLine(
            `[SUCCESS] Assessment completed in ${event.durationSeconds}s`,
            "success",
          );
          onCounts?.(event.summary);
          onProgress?.({
            progress: 100,
            stageId: "reporting",
            stageLabel: "Complete",
          });
          onComplete?.({
            status: event.status,
            durationSeconds: event.durationSeconds,
            summary: event.summary,
            hasReport: event.hasReport,
            findingsCount: event.findingsCount,
          });
          break;

        case "error":
          addLine(`[ERROR] ${event.message}`, "error");
          onError?.(event.message);
          break;

        case "end":
          try {
            socket.close();
          } catch {
            // already closing
          }
          break;

        default:
          break;
      }
    };

    socket.onerror = () => {
      if (cancelled) return;
      addLine(
        "[ERROR] Live connection error — the backend may not be reachable.",
        "error",
      );
      onError?.("Live connection error");
    };

    socket.onclose = (closeEvent) => {
      if (cancelled) return;
      // 4401 = not authorized, 4404 = not found (see backend websocket.py).
      if (closeEvent.code === 4401) {
        addLine("[ERROR] Not authorized to view this engagement.", "error");
        onError?.("Not authorized");
      }
    };

    return () => {
      cancelled = true;
      try {
        socket.close();
      } catch {
        // ignore
      }
    };
  }, [
    mode,
    engagementId,
    target,
    onComplete,
    onProgress,
    onStageChange,
    onCounts,
    onError,
  ]);

  /*
   * Scroll so the newest command/phase marker sits near the top; output
   * lines then flow underneath it.
   */
  useEffect(() => {
    const terminalBody = terminalBodyRef.current;
    const activeCommand = lineRefs.current[activeCommandId];

    if (!terminalBody || !activeCommand) return;

    const desiredTopOffset = terminalBody.clientHeight * 0.16;
    const targetScrollPosition =
      activeCommand.offsetTop - terminalBody.offsetTop - desiredTopOffset;

    terminalBody.scrollTo({
      top: Math.max(0, targetScrollPosition),
      behavior: "smooth",
    });
  }, [activeCommandId]);

  return (
    <div className="w-full overflow-hidden rounded-[14px] border border-white/10 bg-[rgba(8,7,22,0.88)] shadow-[0_32px_90px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.03)] backdrop-blur-[18px]">
      <div className="flex h-[44px] items-center gap-2 border-b border-white/10 bg-white/[0.035] px-[14px]">
        <div className="h-[11px] w-[11px] shrink-0 rounded-full bg-[#ff5f57]" />
        <div className="h-[11px] w-[11px] shrink-0 rounded-full bg-[#ffbd2e]" />
        <div className="h-[11px] w-[11px] shrink-0 rounded-full bg-[#28c840]" />

        <div className="ml-3 truncate font-['JetBrains_Mono'] text-[12px] text-white/40">
          recon@maxim: ~/{target}
        </div>
      </div>

      <div
        ref={terminalBodyRef}
        className={`terminal-body overflow-y-auto p-[22px] text-left font-['JetBrains_Mono'] text-[13px] leading-[1.45] tracking-[-0.15px] text-[#d7dce8] transition-[min-height,max-height] duration-700 max-[560px]:p-[15px] max-[560px]:text-[10.5px] ${
          mode === "scanning"
            ? "min-h-[620px] max-h-[700px] max-[900px]:min-h-[520px] max-[900px]:max-h-[600px] max-[560px]:min-h-[420px] max-[560px]:max-h-[500px]"
            : "min-h-[360px] max-h-[460px] max-[900px]:min-h-[330px] max-[560px]:min-h-[310px] max-[560px]:max-h-[400px]"
        }`}
      >
        {lines.map((line) => (
          <div
            key={line.id}
            ref={(element) => {
              if (element) {
                lineRefs.current[line.id] = element;
              } else {
                delete lineRefs.current[line.id];
              }
            }}
            className={`terminal-line ${line.className}`}
          >
            {line.text}
          </div>
        ))}

        {/* Extra room so the newest command can scroll near the top */}
        {mode === "scanning" && (
          <div
            aria-hidden="true"
            className="h-[430px] max-[900px]:h-[340px] max-[560px]:h-[260px]"
          />
        )}
      </div>
    </div>
  );
}

export default Terminal;
