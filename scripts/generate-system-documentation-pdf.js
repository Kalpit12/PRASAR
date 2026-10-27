/**
 * Build docs/PRASAR-System-Guide.pdf from docs/PRASAR-System-Guide.md
 * Usage: node scripts/generate-system-documentation-pdf.js
 */
const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");

const root = path.join(__dirname, "..");
const docsDir = path.join(root, "docs");
const mdPath = path.join(docsDir, "PRASAR-System-Guide.md");
const outPath = path.join(docsDir, "PRASAR-System-Guide.pdf");

const MARGIN = 48;
const BOTTOM_LIMIT = 820;
const NAVY = "#1A237E";
const SAFFRON = "#E8820C";
const BODY = "#222222";
const MUTED = "#555555";

function stripMdInline(s) {
  return String(s || "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
}

function isTableRow(line) {
  const t = line.trim();
  return t.startsWith("|") && t.endsWith("|");
}

function parseTableRow(line) {
  return line
    .trim()
    .slice(1, -1)
    .split("|")
    .map((c) => stripMdInline(c.trim()));
}

function renderMarkdown(doc, md) {
  const lines = md.split(/\r?\n/);
  let i = 0;
  let inCode = false;
  let codeBuf = [];
  let skippedDocTitle = false;

  const ensureSpace = (h) => {
    if (doc.y + h <= BOTTOM_LIMIT) return;
    if (doc.y <= MARGIN + 8) return;
    doc.addPage();
  };

  const gap = (n = 0.1) => {
    doc.y += n * 12;
  };

  const writeParagraph = (text, opts = {}) => {
    const t = stripMdInline(text).trim();
    if (!t) return;
    ensureSpace(22);
    doc
      .font(opts.bold ? "Helvetica-Bold" : "Helvetica")
      .fontSize(opts.size || 9.5)
      .fillColor(opts.color || BODY)
      .text(t, MARGIN, doc.y, {
        width: doc.page.width - MARGIN * 2,
        lineGap: 2,
      });
    gap(0.06);
  };

  const embedImage = (relPath, caption) => {
    const imgPath = path.join(docsDir, relPath.replace(/^\//, ""));
    if (!fs.existsSync(imgPath)) {
      writeParagraph(`[Screenshot missing: ${relPath}]`, { color: MUTED, size: 8 });
      return;
    }
    const maxW = doc.page.width - MARGIN * 2;
    const maxH = 255;
    const imgMeta = doc.openImage(imgPath);
    const scale = Math.min(maxW / imgMeta.width, maxH / imgMeta.height, 1);
    const w = imgMeta.width * scale;
    const h = imgMeta.height * scale;
    ensureSpace(h + 16);
    gap(0.08);
    const x = MARGIN + (maxW - w) / 2;
    const y = doc.y;
    doc.image(imgPath, x, y, { width: w, height: h });
    doc.y = y + h + 3;
    if (caption) {
      doc
        .font("Helvetica-Oblique")
        .fontSize(8)
        .fillColor(MUTED)
        .text(stripMdInline(caption), MARGIN, doc.y, { width: maxW, align: "center", lineGap: 0 });
      gap(0.05);
    }
  };

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      if (!inCode) {
        inCode = true;
        codeBuf = [];
      } else {
        inCode = false;
        ensureSpace(36);
        doc.font("Courier").fontSize(7.5).fillColor(MUTED);
        doc.text(codeBuf.join("\n"), MARGIN, doc.y, {
          width: doc.page.width - MARGIN * 2,
          lineGap: 0,
        });
        gap(0.12);
      }
      i++;
      continue;
    }
    if (inCode) {
      codeBuf.push(line);
      i++;
      continue;
    }

    if (trimmed === "---") {
      i++;
      continue;
    }

    if (trimmed.startsWith("# ")) {
      if (!skippedDocTitle) {
        skippedDocTitle = true;
        i++;
        continue;
      }
      ensureSpace(24);
      gap(0.1);
      doc.font("Helvetica-Bold").fontSize(16).fillColor(NAVY).text(stripMdInline(trimmed.slice(2)), MARGIN, doc.y);
      gap(0.1);
      i++;
      continue;
    }

    if (trimmed.startsWith("## ")) {
      ensureSpace(20);
      gap(0.1);
      doc.font("Helvetica-Bold").fontSize(12).fillColor(NAVY).text(stripMdInline(trimmed.slice(3)), MARGIN, doc.y);
      gap(0.08);
      i++;
      continue;
    }

    if (trimmed.startsWith("### ")) {
      ensureSpace(16);
      gap(0.06);
      doc.font("Helvetica-Bold").fontSize(10).fillColor(SAFFRON).text(stripMdInline(trimmed.slice(4)), MARGIN, doc.y);
      gap(0.06);
      i++;
      continue;
    }

    const imgMatch = trimmed.match(/^!\[([^\]]*)\]\(([^)]+)\)$/);
    if (imgMatch) {
      embedImage(imgMatch[2], imgMatch[1]);
      i++;
      continue;
    }

    if (isTableRow(trimmed)) {
      const rows = [];
      while (i < lines.length && isTableRow(lines[i].trim())) {
        const row = parseTableRow(lines[i]);
        if (!row.every((c) => /^[-:]+$/.test(c))) rows.push(row);
        i++;
      }
      if (rows.length) {
        ensureSpace(rows.length * 12 + 4);
        doc.font("Helvetica").fontSize(8.5).fillColor(BODY);
        for (const row of rows) {
          doc.text(row.join("  |  "), MARGIN, doc.y, { width: doc.page.width - MARGIN * 2, lineGap: 0 });
        }
        gap(0.08);
      }
      continue;
    }

    if (/^[-*]\s+/.test(trimmed)) {
      writeParagraph(`• ${trimmed.replace(/^[-*]\s+/, "")}`);
      i++;
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      writeParagraph(trimmed);
      i++;
      continue;
    }

    if (!trimmed) {
      i++;
      continue;
    }

    writeParagraph(trimmed);
    i++;
  }
}

function addCover(doc) {
  const w = doc.page.width;
  doc.rect(0, 0, w, 88).fill(NAVY);
  doc.font("Helvetica-Bold").fontSize(22).fillColor("#FFFFFF").text("PRASAR", MARGIN, 22);
  doc.font("Helvetica").fontSize(10).fillColor("#C9A84C").text("PR Volunteer User Guide", MARGIN, 50);
  doc.font("Helvetica").fontSize(8.5).fillColor(MUTED).text("BAPS Africa · Dignitary outreach workflow", MARGIN, 66);
  doc.y = 98;
}

async function main() {
  if (!fs.existsSync(mdPath)) {
    throw new Error(`Missing ${mdPath}`);
  }
  const md = fs.readFileSync(mdPath, "utf8");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  const doc = new PDFDocument({ size: "A4", margin: MARGIN });
  const tmpPath = `${outPath}.tmp`;
  const out = fs.createWriteStream(tmpPath);
  doc.pipe(out);

  addCover(doc);
  renderMarkdown(doc, md);

  doc.end();
  await new Promise((resolve, reject) => {
    out.on("finish", resolve);
    out.on("error", reject);
  });
  fs.renameSync(tmpPath, outPath);
  console.log("Wrote:", outPath);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
