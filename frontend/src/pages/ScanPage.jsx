import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Navigate,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  AnimatePresence,
  motion,
} from "framer-motion";

import Terminal from "../components/Terminal";
import ScanResults from "../components/ScanResults";
import { createEngagement } from "../services/scanService";

const scanStages = [
  {
    id: "validation",
    label: "Target validation",
    shortLabel: "Validation",
  },
  {
    id: "recon",
    label: "Reconnaissance",
    shortLabel: "Recon",
  },
  {
    id: "enumeration",
    label: "Enumeration",
    shortLabel: "Enumeration",
  },
  {
    id: "vuln_analysis",
    label: "Vulnerability analysis",
    shortLabel: "Vuln analysis",
  },
  {
    id: "exploitation",
    label: "Exploitation",
    shortLabel: "Exploitation",
  },
  {
    id: "reporting",
    label: "Report generation",
    shortLabel: "Reporting",
  },
];

function formatTime(seconds) {
  const safeSeconds = Math.max(
    0,
    Math.floor(Number(seconds) || 0),
  );

  const minutes = Math.floor(
    safeSeconds / 60,
  );

  const remainingSeconds =
    safeSeconds % 60;

  return `${String(minutes).padStart(
    2,
    "0",
  )}:${String(
    remainingSeconds,
  ).padStart(2, "0")}`;
}

function ScanPage() {
  const location = useLocation();
  const navigate = useNavigate();

  const target = location.state?.target;

  const [
    scanComplete,
    setScanComplete,
  ] = useState(false);

  const [scanResult, setScanResult] =
    useState(null);

  const [progress, setProgress] =
    useState(0);

  const [
    currentStageId,
    setCurrentStageId,
  ] = useState("validation");

  const [
    currentStageLabel,
    setCurrentStageLabel,
  ] = useState("Preparing scan");

  const [processed, setProcessed] =
    useState(0);

  const [total, setTotal] =
    useState(0);

  const [
    elapsedSeconds,
    setElapsedSeconds,
  ] = useState(0);

  const [
    completedStages,
    setCompletedStages,
  ] = useState([]);

  const [
    showTerminal,
    setShowTerminal,
  ] = useState(true);

  const [engagementId, setEngagementId] =
    useState(null);

  const [scanError, setScanError] =
    useState(null);

  const [liveSummary, setLiveSummary] =
    useState(null);

  // Create the engagement once (guarded against StrictMode's double effect).
  const createStartedRef = useRef(false);

  useEffect(() => {
    if (!target || createStartedRef.current) return;
    createStartedRef.current = true;

    createEngagement(target)
      .then((engagement) => {
        setEngagementId(engagement.id);
      })
      .catch((error) => {
        setScanError(
          error?.message ||
            "Could not start the scan. Please try again.",
        );
      });
  }, [target]);

  // Client-side elapsed timer (the backend streams phases, not a clock).
  useEffect(() => {
    if (scanComplete || !engagementId) return undefined;

    const startedAt = Date.now();
    const intervalId = window.setInterval(() => {
      setElapsedSeconds(
        Math.floor((Date.now() - startedAt) / 1000),
      );
    }, 1000);

    return () => window.clearInterval(intervalId);
  }, [scanComplete, engagementId]);

  const handleCounts = useCallback((counts) => {
    if (!counts) return;
    setLiveSummary(counts);

    const discovered =
      (counts.subdomains ?? 0) +
      (counts.liveHosts ?? 0) +
      (counts.urls ?? 0) +
      (counts.openPorts ?? 0);

    setProcessed(discovered);
    setTotal(discovered);
  }, []);

  const handleScanError = useCallback((message) => {
    setScanError(message || "Scan failed");
  }, []);

  const handleProgress = useCallback(
    (progressData) => {
      if (progressData.progress != null) {
        setProgress(progressData.progress);
      }

      if (progressData.stageId) {
        setCurrentStageId(progressData.stageId);
      }

      if (progressData.stageLabel) {
        setCurrentStageLabel(
          progressData.stageLabel,
        );
      }
    },
    [],
  );

  const handleStageChange = useCallback(
    (stage) => {
      setCurrentStageId(stage.id);
      setCurrentStageLabel(stage.label);

      // Backend sends the authoritative list of finished stages.
      if (Array.isArray(stage.completedStages)) {
        setCompletedStages(stage.completedStages);
      }
    },
    [],
  );

  const handleScanComplete =
    useCallback((result) => {
      setScanComplete(true);
      setScanResult(result);

      setProgress(100);
      setCurrentStageId(
        "completed",
      );
      setCurrentStageLabel(
        "Scan complete",
      );

      setElapsedSeconds(
        result?.durationSeconds ?? 0,
      );

      setCompletedStages(
        scanStages.map(
          (stage) => stage.id,
        ),
      );

      /*
       * Automatically collapse the terminal
       * after the completion state is visible.
       *
       * The Terminal component remains mounted,
       * so showing it again will not restart
       * the scan.
       */
      window.setTimeout(() => {
        setShowTerminal(false);
      }, 1300);
    }, []);

  const summary = useMemo(() => {
    return (
      scanResult?.summary ??
      liveSummary ?? {
        subdomains: 0,
        liveHosts: 0,
        urls: 0,
        openPorts: 0,
      }
    );
  }, [scanResult, liveSummary]);

  const handleToggleTerminal =
    useCallback(() => {
      setShowTerminal(
        (currentValue) =>
          !currentValue,
      );
    }, []);

  const handleNewScan =
    useCallback(() => {
      navigate("/");
    }, [navigate]);

  if (!target) {
    return (
      <Navigate
        to="/"
        replace
      />
    );
  }

  return (
    <motion.section
      initial={{
        opacity: 0,
      }}
      animate={{
        opacity: 1,
      }}
      transition={{
        duration: 0.35,
        ease: [
          0.22,
          1,
          0.36,
          1,
        ],
      }}
      className="min-h-screen text-white"
    >
      {/* Target status bar */}
      <div className="relative z-40 flex justify-center px-4 pb-5 pt-[110px] max-[900px]:pt-[96px]">
        <motion.div
          layoutId="scan-target-box"
          transition={{
            layout: {
              duration: 0.7,
              ease: [
                0.22,
                1,
                0.36,
                1,
              ],
            },
          }}
          className="
            flex w-[500px] max-w-full
            items-center gap-2
            rounded-full
            border border-white/10
            bg-white/[0.08]
            p-[10px]
            shadow-[0_20px_70px_rgba(0,0,0,0.28)]
            backdrop-blur-[18px]
            max-[560px]:p-[7px]
          "
        >
          <motion.div
            layoutId="scan-target-text"
            className="
              min-w-0 flex-1
              truncate bg-transparent
              px-[14px] text-left
              text-[14px] text-white
              max-[560px]:px-[9px]
              max-[560px]:text-[12px]
            "
          >
            {target}
          </motion.div>

          <motion.div
            layoutId="scan-status-button"
            className={`
              inline-flex shrink-0
              items-center justify-center
              gap-2 rounded-full
              px-[18px] py-3
              text-[14px] font-bold
              max-[560px]:px-[14px]
              max-[560px]:py-[11px]
              max-[560px]:text-[12px]
              ${
                scanComplete
                  ? "bg-[#7ee787] text-[#102814]"
                  : "bg-white text-[#181468]"
              }
            `}
          >
            <span
              className={`
                h-2 w-2 rounded-full
                ${
                  scanComplete
                    ? "bg-[#102814]"
                    : "animate-pulse bg-[#181468]"
                }
              `}
            />

            {scanComplete
              ? "Complete"
              : "Scanning"}
          </motion.div>
        </motion.div>
      </div>

      {/* Error banner */}
      {scanError && (
        <div className="mx-auto mb-2 w-full max-w-[900px] px-6">
          <div className="rounded-[12px] border border-[#ff5f57]/30 bg-[#ff5f57]/[0.08] px-5 py-4 text-[13px] text-[#ffb3ae]">
            <span className="font-semibold">Scan error:</span> {scanError}
          </div>
        </div>
      )}

      {/* Terminal and progress workspace */}
      <motion.div
        initial={false}
        animate={{
          opacity:
            scanComplete &&
            !showTerminal
              ? 0
              : 1,

          height:
            scanComplete &&
            !showTerminal
              ? 0
              : "auto",

          marginBottom:
            scanComplete &&
            !showTerminal
              ? 0
              : 48,
        }}
        transition={{
          duration: 0.7,
          ease: [
            0.22,
            1,
            0.36,
            1,
          ],
        }}
        className="
          mx-auto w-full
          overflow-hidden
          px-6 pt-4
          lg:px-10 xl:px-12
        "
      >
        <motion.div
          initial={{
            opacity: 0,
            y: 28,
            scale: 0.985,
          }}
          animate={{
            opacity: 1,
            y: 0,
            scale: 1,
          }}
          transition={{
            duration: 0.65,
            ease: [
              0.22,
              1,
              0.36,
              1,
            ],
          }}
          className="
            mx-auto flex w-full
            max-w-[1650px]
            flex-col gap-4
            lg:flex-row
          "
        >
          {/* Live terminal */}
          <motion.div
            layout
            className="min-w-0 flex-1"
          >
            <Terminal
              mode="scanning"
              target={target}
              engagementId={engagementId}
              onComplete={
                handleScanComplete
              }
              onProgress={
                handleProgress
              }
              onStageChange={
                handleStageChange
              }
              onCounts={handleCounts}
              onError={handleScanError}
            />
          </motion.div>

          {/* Vertical progress rail */}
          <motion.aside
            initial={{
              opacity: 0,
              x: 36,
            }}
            animate={{
              opacity: 1,
              x: 0,
            }}
            transition={{
              duration: 0.6,
              delay: 0.12,
              ease: [
                0.22,
                1,
                0.36,
                1,
              ],
            }}
            className="
              relative w-full
              overflow-hidden
              rounded-[14px]
              border
              border-[#8ab4ff]/15
              bg-[rgba(5,6,18,0.82)]
              shadow-[0_24px_70px_rgba(0,0,0,0.3)]
              backdrop-blur-[18px]
              lg:w-[230px]
              lg:shrink-0
            "
          >
            {/* Moving scanner beam */}
            {!scanComplete && (
              <motion.div
                className="
                  pointer-events-none
                  absolute left-0 top-0
                  h-full w-px
                  bg-gradient-to-b
                  from-transparent
                  via-[#8ab4ff]/80
                  to-transparent
                "
                animate={{
                  x: [0, 230, 0],
                  opacity: [
                    0.15,
                    0.85,
                    0.15,
                  ],
                }}
                transition={{
                  duration: 3.2,
                  repeat: Infinity,
                  ease: "linear",
                }}
              />
            )}

            {/* Progress rail header */}
            <div className="border-b border-white/[0.07] px-5 py-4">
              <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.18em] text-white/25">
                Pipeline status
              </p>

              <div className="mt-2 flex items-end justify-between">
                <p
                  className={`
                    font-['JetBrains_Mono']
                    text-[36px] font-semibold
                    tracking-[-2px]
                    ${
                      scanComplete
                        ? "text-[#7ee787]"
                        : "text-[#8ab4ff]"
                    }
                  `}
                >
                  {String(
                    Math.round(
                      progress,
                    ),
                  ).padStart(
                    3,
                    "0",
                  )}
                </p>

                <span className="pb-1 font-['JetBrains_Mono'] text-[13px] text-white/30">
                  %
                </span>
              </div>
            </div>

            <div className="p-5">
              <div className="flex gap-4">
                {/* Segmented progress bar */}
                <div
                  className="
                    flex h-[320px]
                    w-[14px]
                    flex-col-reverse
                    gap-[3px]
                    max-lg:h-[14px]
                    max-lg:w-full
                    max-lg:flex-row
                  "
                >
                  {Array.from({
                    length: 32,
                  }).map(
                    (_, index) => {
                      const segmentValue =
                        ((index + 1) /
                          32) *
                        100;

                      const isFilled =
                        progress >=
                        segmentValue;

                      return (
                        <motion.div
                          key={index}
                          className={`
                            min-h-0 flex-1
                            rounded-[1px]
                            ${
                              isFilled
                                ? scanComplete
                                  ? "bg-[#7ee787]"
                                  : "bg-[#8ab4ff]"
                                : "bg-white/[0.055]"
                            }
                          `}
                          animate={
                            isFilled &&
                            !scanComplete
                              ? {
                                  opacity:
                                    [
                                      0.45,
                                      1,
                                      0.45,
                                    ],
                                }
                              : {
                                  opacity: 1,
                                }
                          }
                          transition={{
                            duration: 1,

                            repeat:
                              isFilled &&
                              !scanComplete
                                ? Infinity
                                : 0,

                            delay:
                              index *
                              0.018,
                          }}
                        />
                      );
                    },
                  )}
                </div>

                {/* Desktop progress details */}
                <div className="min-w-0 flex-1 max-lg:hidden">
                  <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.15em] text-white/20">
                    Active module
                  </p>

                  <p className="mt-2 break-words font-['JetBrains_Mono'] text-[12px] leading-5 text-white/70">
                    {
                      currentStageLabel
                    }
                  </p>

                  <div className="mt-7 space-y-5">
                    <div>
                      <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.14em] text-white/20">
                        Objects
                      </p>

                      <p className="mt-1 font-['JetBrains_Mono'] text-[12px] text-white/65">
                        {total > 0
                          ? `${processed}/${total}`
                          : "0/0"}
                      </p>
                    </div>

                    <div>
                      <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.14em] text-white/20">
                        Elapsed
                      </p>

                      <p className="mt-1 font-['JetBrains_Mono'] text-[12px] text-white/65">
                        {formatTime(
                          elapsedSeconds,
                        )}
                      </p>
                    </div>

                    <div>
                      <p className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-[0.14em] text-white/20">
                        Stages
                      </p>

                      <p className="mt-1 font-['JetBrains_Mono'] text-[12px] text-white/65">
                        {
                          completedStages.length
                        }
                        /
                        {
                          scanStages.length
                        }
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Mobile progress details */}
              <div className="mt-4 hidden grid-cols-3 gap-3 border-t border-white/[0.06] pt-4 max-lg:grid">
                <div>
                  <p className="font-['JetBrains_Mono'] text-[8px] uppercase tracking-[0.12em] text-white/20">
                    Module
                  </p>

                  <p className="mt-1 truncate font-['JetBrains_Mono'] text-[10px] text-white/65">
                    {
                      currentStageLabel
                    }
                  </p>
                </div>

                <div>
                  <p className="font-['JetBrains_Mono'] text-[8px] uppercase tracking-[0.12em] text-white/20">
                    Objects
                  </p>

                  <p className="mt-1 font-['JetBrains_Mono'] text-[10px] text-white/65">
                    {total > 0
                      ? `${processed}/${total}`
                      : "0/0"}
                  </p>
                </div>

                <div>
                  <p className="font-['JetBrains_Mono'] text-[8px] uppercase tracking-[0.12em] text-white/20">
                    Elapsed
                  </p>

                  <p className="mt-1 font-['JetBrains_Mono'] text-[10px] text-white/65">
                    {formatTime(
                      elapsedSeconds,
                    )}
                  </p>
                </div>
              </div>

              {/* Stream state */}
              <div className="mt-5 border-t border-white/[0.06] pt-4">
                <div className="flex items-center gap-2">
                  <span
                    className={`
                      h-2 w-2 rounded-full
                      ${
                        scanComplete
                          ? "bg-[#7ee787]"
                          : "animate-pulse bg-[#8ab4ff]"
                      }
                    `}
                  />

                  <span
                    className={`
                      font-['JetBrains_Mono']
                      text-[10px] uppercase
                      tracking-[0.12em]
                      ${
                        scanComplete
                          ? "text-[#7ee787]"
                          : "text-[#8ab4ff]"
                      }
                    `}
                  >
                    {scanComplete
                      ? "exit 0"
                      : "stream active"}
                  </span>
                </div>
              </div>
            </div>
          </motion.aside>
        </motion.div>
      </motion.div>

      {/* Compact pipeline strip */}
      <AnimatePresence>
        {!scanComplete && (
          <motion.section
            initial={{
              opacity: 0,
              y: 20,
            }}
            animate={{
              opacity: 1,
              y: 0,
            }}
            exit={{
              opacity: 0,
              y: -20,
              height: 0,
            }}
            transition={{
              duration: 0.5,
            }}
            className="
              mx-auto w-full
              max-w-[1320px]
              overflow-hidden
              px-6 pb-24
              lg:px-10
            "
          >
            <div className="border-y border-white/[0.08] bg-white/[0.018] backdrop-blur-[14px]">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
                {scanStages.map(
                  (stage, index) => {
                    const isDone =
                      completedStages.includes(
                        stage.id,
                      );

                    const isActive =
                      currentStageId ===
                        stage.id &&
                      !isDone;

                    return (
                      <div
                        key={stage.id}
                        className="relative px-5 py-5"
                      >
                        {index !==
                          scanStages.length -
                            1 && (
                          <div className="absolute right-0 top-[25%] hidden h-1/2 w-px bg-white/[0.07] lg:block" />
                        )}

                        <div className="flex items-center gap-2">
                          <span
                            className={`
                              h-1.5 w-1.5
                              rounded-full
                              ${
                                isDone
                                  ? "bg-[#7ee787]"
                                  : isActive
                                    ? "animate-pulse bg-[#8ab4ff]"
                                    : "bg-white/15"
                              }
                            `}
                          />

                          <span
                            className={`
                              font-['JetBrains_Mono']
                              text-[9px] uppercase
                              tracking-[0.12em]
                              ${
                                isDone
                                  ? "text-[#7ee787]/70"
                                  : isActive
                                    ? "text-[#8ab4ff]"
                                    : "text-white/25"
                              }
                            `}
                          >
                            {isDone
                              ? "Done"
                              : isActive
                                ? "Running"
                                : "Waiting"}
                          </span>
                        </div>

                        <p
                          className={`
                            mt-3 text-[12px]
                            ${
                              isDone ||
                              isActive
                                ? "text-white/70"
                                : "text-white/30"
                            }
                          `}
                        >
                          {
                            stage.shortLabel
                          }
                        </p>
                      </div>
                    );
                  },
                )}
              </div>
            </div>
          </motion.section>
        )}
      </AnimatePresence>

      {/* Separate results component */}
      <AnimatePresence>
        {scanComplete && (
          <ScanResults
            target={target}
            engagementId={engagementId}
            scanResult={scanResult}
            summary={summary}
            elapsedSeconds={
              elapsedSeconds
            }
            showTerminal={
              showTerminal
            }
            onToggleTerminal={
              handleToggleTerminal
            }
            onNewScan={
              handleNewScan
            }
          />
        )}
      </AnimatePresence>
    </motion.section>
  );
}

export default ScanPage;