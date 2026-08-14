// Compact, dependency-free markdown renderer for the generated report.
//
// It builds React elements (never dangerouslySetInnerHTML), so target-controlled
// text that ends up in the report can't inject markup. Supports the subset the
// reporting model actually emits: headings, bold/italic/code, links, ordered &
// unordered lists, tables, blockquotes, fenced code, and horizontal rules.

let keySeq = 0;
const nextKey = () => {
  keySeq += 1;
  return `md-${keySeq}`;
};

// --- Inline formatting: **bold**, *italic*/_italic_, `code`, [text](url) ---
function renderInline(text) {
  const nodes = [];
  const pattern =
    /(\*\*([^*]+)\*\*|__([^_]+)__|\*([^*]+)\*|_([^_]+)_|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\))/g;

  let lastIndex = 0;
  let match;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }

    if (match[2] || match[3]) {
      nodes.push(
        <strong key={nextKey()} className="font-semibold text-white">
          {match[2] || match[3]}
        </strong>,
      );
    } else if (match[4] || match[5]) {
      nodes.push(
        <em key={nextKey()} className="italic text-white/80">
          {match[4] || match[5]}
        </em>,
      );
    } else if (match[6]) {
      nodes.push(
        <code
          key={nextKey()}
          className="rounded bg-white/[0.08] px-1.5 py-0.5 font-['JetBrains_Mono'] text-[12px] text-[#8ab4ff]"
        >
          {match[6]}
        </code>,
      );
    } else if (match[7] && match[8]) {
      const href = match[8];
      const safe = /^(https?:|mailto:)/i.test(href) ? href : "#";
      nodes.push(
        <a
          key={nextKey()}
          href={safe}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#8ab4ff] underline decoration-white/20 underline-offset-2 hover:decoration-[#8ab4ff]"
        >
          {match[7]}
        </a>,
      );
    }

    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes;
}

const headingClasses = {
  1: "mt-2 mb-4 text-[26px] font-semibold tracking-[-0.8px] text-white",
  2: "mt-8 mb-3 border-b border-white/[0.08] pb-2 text-[20px] font-semibold text-white",
  3: "mt-6 mb-2 text-[16px] font-semibold text-white/90",
  4: "mt-5 mb-2 text-[14px] font-semibold text-white/80",
  5: "mt-4 mb-1 text-[13px] font-semibold text-white/70",
  6: "mt-4 mb-1 text-[12px] font-semibold uppercase tracking-wide text-white/60",
};

function parseTable(lines, startIndex) {
  // A table needs a header row, a |---|---| separator, then body rows.
  const splitRow = (row) =>
    row
      .trim()
      .replace(/^\||\|$/g, "")
      .split("|")
      .map((cell) => cell.trim());

  const header = splitRow(lines[startIndex]);
  const body = [];
  let i = startIndex + 2;
  while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
    body.push(splitRow(lines[i]));
    i += 1;
  }

  const table = (
    <div key={nextKey()} className="my-4 overflow-x-auto">
      <table className="w-full border-collapse text-left text-[12px]">
        <thead>
          <tr>
            {header.map((cell) => (
              <th
                key={nextKey()}
                className="border-b border-white/[0.12] px-3 py-2 font-['JetBrains_Mono'] text-[10px] uppercase tracking-[0.08em] text-white/45"
              >
                {renderInline(cell)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {body.map((cells) => (
            <tr key={nextKey()}>
              {cells.map((cell) => (
                <td
                  key={nextKey()}
                  className="border-b border-white/[0.055] px-3 py-2 align-top text-white/65"
                >
                  {renderInline(cell)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  return { node: table, nextIndex: i };
}

function parseMarkdown(markdown) {
  const lines = (markdown || "").replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Fenced code block
    if (trimmed.startsWith("```")) {
      const code = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        code.push(lines[i]);
        i += 1;
      }
      i += 1; // skip closing fence
      blocks.push(
        <pre
          key={nextKey()}
          className="my-4 overflow-x-auto rounded-[10px] border border-white/[0.08] bg-black/40 p-4 font-['JetBrains_Mono'] text-[12px] leading-relaxed text-white/70"
        >
          <code>{code.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    // Blank line
    if (!trimmed) {
      i += 1;
      continue;
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      blocks.push(
        <hr key={nextKey()} className="my-6 border-white/[0.08]" />,
      );
      i += 1;
      continue;
    }

    // Heading
    const headingMatch = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const Tag = `h${level}`;
      blocks.push(
        <Tag key={nextKey()} className={headingClasses[level]}>
          {renderInline(headingMatch[2])}
        </Tag>,
      );
      i += 1;
      continue;
    }

    // Table (header row followed by a separator row)
    if (
      trimmed.includes("|") &&
      i + 1 < lines.length &&
      /^\s*\|?[\s:-]*\|[\s:|-]*$/.test(lines[i + 1]) &&
      lines[i + 1].includes("-")
    ) {
      const { node, nextIndex } = parseTable(lines, i);
      blocks.push(node);
      i = nextIndex;
      continue;
    }

    // Blockquote
    if (trimmed.startsWith(">")) {
      const quote = [];
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        quote.push(lines[i].trim().replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push(
        <blockquote
          key={nextKey()}
          className="my-4 border-l-2 border-[#8ab4ff]/40 pl-4 text-[13px] italic text-white/55"
        >
          {renderInline(quote.join(" "))}
        </blockquote>,
      );
      continue;
    }

    // Unordered list
    if (/^[-*+]\s+/.test(trimmed)) {
      const items = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(lines[i].trim().replace(/^[-*+]\s+/, ""));
        i += 1;
      }
      blocks.push(
        <ul
          key={nextKey()}
          className="my-3 list-disc space-y-1.5 pl-6 text-[13px] leading-6 text-white/65 marker:text-white/30"
        >
          {items.map((item) => (
            <li key={nextKey()}>{renderInline(item)}</li>
          ))}
        </ul>,
      );
      continue;
    }

    // Ordered list
    if (/^\d+[.)]\s+/.test(trimmed)) {
      const items = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) {
        items.push(lines[i].trim().replace(/^\d+[.)]\s+/, ""));
        i += 1;
      }
      blocks.push(
        <ol
          key={nextKey()}
          className="my-3 list-decimal space-y-1.5 pl-6 text-[13px] leading-6 text-white/65 marker:text-white/30"
        >
          {items.map((item) => (
            <li key={nextKey()}>{renderInline(item)}</li>
          ))}
        </ol>,
      );
      continue;
    }

    // Paragraph — gather consecutive non-blank, non-structural lines.
    const paragraph = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].trim().startsWith("#") &&
      !lines[i].trim().startsWith("```") &&
      !/^\s*[-*+]\s+/.test(lines[i]) &&
      !/^\s*\d+[.)]\s+/.test(lines[i]) &&
      !lines[i].trim().startsWith(">")
    ) {
      paragraph.push(lines[i].trim());
      i += 1;
    }
    if (paragraph.length) {
      blocks.push(
        <p
          key={nextKey()}
          className="my-3 text-[13px] leading-6 text-white/65"
        >
          {renderInline(paragraph.join(" "))}
        </p>,
      );
    }
  }

  return blocks;
}

function MarkdownView({ markdown }) {
  keySeq = 0;
  return <div className="max-w-none">{parseMarkdown(markdown)}</div>;
}

export default MarkdownView;
