/**
 * Build docs/PRASAR-System-Guide.docx from docs/PRASAR-System-Guide.md
 * Usage: node scripts/generate-system-documentation-docx.js
 */
const fs = require("fs");
const path = require("path");
const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  ImageRun,
  Table,
  TableRow,
  TableCell,
  WidthType,
  AlignmentType,
  ShadingType,
} = require("docx");

const root = path.join(__dirname, "..");
const docsDir = path.join(root, "docs");
const mdPath = path.join(docsDir, "PRASAR-System-Guide.md");
const outPath = path.join(docsDir, "PRASAR-System-Guide.docx");

const MAX_IMG_W = 520;
const MAX_IMG_H = 360;

function stripMdInline(s) {
  return String(s || "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
}

function parseInlineRuns(text) {
  const src = String(text || "");
  const runs = [];
  const re = /\*\*([^*]+)\*\*/g;
  let last = 0;
  let m;
  while ((m = re.exec(src))) {
    if (m.index > last) runs.push(new TextRun(src.slice(last, m.index)));
    runs.push(new TextRun({ text: m[1], bold: true }));
    last = m.index + m[0].length;
  }
  if (last < src.length) runs.push(new TextRun(src.slice(last)));
  return runs.length ? runs : [new TextRun("")];
}

function pngDimensions(buf) {
  if (buf.length < 24 || buf.readUInt32BE(0) !== 0x89504e47) return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

function jpegDimensions(buf) {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  let i = 2;
  while (i < buf.length - 8) {
    if (buf[i] !== 0xff) break;
    const marker = buf[i + 1];
    const len = buf.readUInt16BE(i + 2);
    if (marker >= 0xc0 && marker <= 0xc3) {
      return { height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
    }
    i += 2 + len;
  }
  return null;
}

function scaleImage(w, h) {
  const scale = Math.min(MAX_IMG_W / w, MAX_IMG_H / h, 1);
  return { width: Math.round(w * scale), height: Math.round(h * scale) };
}

function imageParagraph(relPath, caption) {
  const imgPath = path.join(docsDir, relPath.replace(/^\//, ""));
  if (!fs.existsSync(imgPath)) {
    return new Paragraph({
      children: [new TextRun({ text: `[Screenshot missing: ${relPath}]`, italics: true, color: "555555" })],
    });
  }
  const data = fs.readFileSync(imgPath);
  const ext = path.extname(imgPath).toLowerCase();
  const type = ext === ".jpg" || ext === ".jpeg" ? "jpg" : "png";
  const dim = type === "png" ? pngDimensions(data) : jpegDimensions(data);
  const w = dim?.width || MAX_IMG_W;
  const h = dim?.height || MAX_IMG_H;
  const { width, height } = scaleImage(w, h);
  const children = [
    new ImageRun({
      type,
      data,
      transformation: { width, height },
    }),
  ];
  const blocks = [
    new Paragraph({ alignment: AlignmentType.CENTER, children }),
  ];
  if (caption) {
    blocks.push(
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: stripMdInline(caption), italics: true, size: 18, color: "555555" })],
      })
    );
  }
  return blocks;
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
    .map((c) => c.trim());
}

function tableBlock(rows) {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map(
      (row, ri) =>
        new TableRow({
          children: row.map(
            (cell) =>
              new TableCell({
                children: [
                  new Paragraph({
                    children: parseInlineRuns(ri === 0 ? cell : stripMdInline(cell)),
                  }),
                ],
              })
          ),
        })
    ),
  });
}

function coverParagraphs() {
  return [
    new Paragraph({
      shading: { type: ShadingType.CLEAR, fill: "1A237E" },
      spacing: { before: 0, after: 120 },
      children: [
        new TextRun({ text: "PRASAR", bold: true, size: 44, color: "FFFFFF" }),
      ],
    }),
    new Paragraph({
      shading: { type: ShadingType.CLEAR, fill: "1A237E" },
      children: [
        new TextRun({ text: "PR Volunteer User Guide", size: 22, color: "C9A84C" }),
      ],
    }),
    new Paragraph({
      shading: { type: ShadingType.CLEAR, fill: "1A237E" },
      spacing: { after: 400 },
      children: [
        new TextRun({ text: "BAPS Africa · Dignitary outreach workflow", size: 18, color: "555555" }),
      ],
    }),
  ];
}

function markdownToDocxChildren(md) {
  const lines = md.split(/\r?\n/);
  const children = [];
  let i = 0;
  let inCode = false;
  let codeBuf = [];
  let skippedDocTitle = false;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      if (!inCode) {
        inCode = true;
        codeBuf = [];
      } else {
        inCode = false;
        children.push(
          new Paragraph({
            children: [new TextRun({ text: codeBuf.join("\n"), font: "Courier New", size: 18, color: "555555" })],
          })
        );
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
      children.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun({ text: stripMdInline(trimmed.slice(2)), bold: true, color: "1A237E" })],
        })
      );
      i++;
      continue;
    }

    if (trimmed.startsWith("## ")) {
      children.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_2,
          children: [new TextRun({ text: stripMdInline(trimmed.slice(3)), bold: true, color: "1A237E" })],
        })
      );
      i++;
      continue;
    }

    if (trimmed.startsWith("### ")) {
      children.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_3,
          children: [new TextRun({ text: stripMdInline(trimmed.slice(4)), bold: true, color: "E8820C" })],
        })
      );
      i++;
      continue;
    }

    const imgMatch = trimmed.match(/^!\[([^\]]*)\]\(([^)]+)\)$/);
    if (imgMatch) {
      children.push(...imageParagraph(imgMatch[2], imgMatch[1]));
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
      if (rows.length) children.push(tableBlock(rows));
      continue;
    }

    if (/^[-*]\s+/.test(trimmed)) {
      children.push(
        new Paragraph({
          children: parseInlineRuns(`• ${trimmed.replace(/^[-*]\s+/, "")}`),
        })
      );
      i++;
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      children.push(new Paragraph({ children: parseInlineRuns(trimmed) }));
      i++;
      continue;
    }

    if (!trimmed) {
      i++;
      continue;
    }

    children.push(new Paragraph({ children: parseInlineRuns(trimmed) }));
    i++;
  }

  return children;
}

async function main() {
  if (!fs.existsSync(mdPath)) {
    throw new Error(`Missing ${mdPath}`);
  }
  const md = fs.readFileSync(mdPath, "utf8");
  const doc = new Document({
    sections: [
      {
        children: [...coverParagraphs(), ...markdownToDocxChildren(md)],
      },
    ],
  });
  const buf = await Packer.toBuffer(doc);
  fs.writeFileSync(outPath, buf);
  console.log("Wrote:", outPath);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
