/**
 * Branded invitation HTML email + PDF buffer for dignitary communications.
 * Logo: public/BAPS.png — use PUBLIC_APP_URL (e.g. https://prasar.onrender.com) on live
 * so the email uses an absolute image URL; otherwise embeds base64 if the file exists.
 */

const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");

function readLogoBuffer() {
  try {
    const p = path.join(__dirname, "..", "public", "BAPS.png");
    if (fs.existsSync(p)) return fs.readFileSync(p);
  } catch (_e) {}
  return null;
}

const logoBuffer = readLogoBuffer();

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateDisplay(raw) {
  const s = String(raw || "").trim();
  if (!s) return "—";
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) {
    return d.toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  }
  return s;
}

/** Header logo for HTML email: public URL preferred for inbox clients; else inline PNG. */
function buildLogoHtmlForEmail() {
  const base = (
    String(process.env.PUBLIC_APP_URL || "").trim() ||
    String(process.env.RENDER_EXTERNAL_URL || "").trim()
  ).replace(/\/+$/, "");
  if (base) {
    const src = `${base}/local-app/BAPS.png`;
    return `<img src="${escapeHtml(src)}" width="72" alt="BAPS Swaminarayan Sanstha" style="display:block;margin:0 auto 14px;border:0;outline:none;text-decoration:none;height:auto;max-width:96px;" />`;
  }
  if (logoBuffer && logoBuffer.length && logoBuffer.length < 500000) {
    return `<img src="data:image/png;base64,${logoBuffer.toString("base64")}" width="72" alt="BAPS Swaminarayan Sanstha" style="display:block;margin:0 auto 14px;border:0;height:auto;max-width:96px;" />`;
  }
  return "";
}

/**
 * @param {object} invite — rows from invitations join (snake_case fields ok)
 */
function buildInvitationEmailHtml(invite) {
  const logoBlock = buildLogoHtmlForEmail();
  const name = escapeHtml(invite.dignitary_name);
  const title = escapeHtml(invite.event_title);
  const venue = escapeHtml(invite.venue);
  const time = escapeHtml(invite.event_time || "");
  const date = escapeHtml(formatDateDisplay(invite.event_date));
  const custom = String(invite.custom_message || "").trim();
  const msgBlock = custom
    ? `<p style="margin:20px 0 0;font-size:15px;line-height:1.65;color:#444;">${escapeHtml(custom).replace(/\n/g, "<br/>")}</p>`
    : `<p style="margin:20px 0 0;font-size:15px;line-height:1.65;color:#444;">The BAPS Swaminarayan Sanstha cordially invites you to grace this occasion.</p>`;
  const timeRow = time
    ? `<tr><td style="width:40px;vertical-align:top;font-size:15px;color:#1A237E;">●</td><td style="font-size:15px;color:#444;padding-bottom:10px;"><strong style="color:#1A237E;">Time</strong><br/><span style="color:#333;">${time}</span></td></tr>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invitation</title>
</head>
<body style="margin:0;padding:0;background:#ede8df;">
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#ede8df;padding:28px 12px;">
<tr><td align="center">
<table role="presentation" cellpadding="0" cellspacing="0" width="600" style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e0d8cc;">
<tr>
<td style="background:#1A237E;padding:28px 28px 32px;text-align:center;">
${logoBlock}
<p style="margin:0;font-size:10px;letter-spacing:3px;color:#C9A84C;text-transform:uppercase;font-family:Arial,sans-serif;">BAPS Swaminarayan Sanstha · Africa</p>
<h1 style="margin:10px 0 0;font-size:28px;font-weight:700;color:#ffffff;font-family:Georgia,'Times New Roman',serif;letter-spacing:0.5px;">PRASAR</h1>
<p style="margin:10px 0 0;font-size:12px;line-height:1.5;color:rgba(255,255,255,0.92);font-family:Arial,sans-serif;letter-spacing:0.2px;max-width:420px;margin-left:auto;margin-right:auto;">Digital Outreach With A Devotional Heart.</p>
</td>
</tr>
<tr>
<td style="padding:36px 32px 40px;font-family:Georgia,'Times New Roman',serif;">
<p style="margin:0;font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px;font-family:Arial,sans-serif;">Dear</p>
<p style="margin:6px 0 0;font-size:24px;font-weight:700;color:#1A237E;line-height:1.2;">${name}</p>
${msgBlock}
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin-top:28px;background:#FDF8F0;border:1px solid #E8E0D4;border-radius:12px;">
<tr><td style="padding:22px 24px;">
<p style="margin:0 0 14px;font-size:11px;letter-spacing:2px;color:#E8820C;text-transform:uppercase;font-weight:bold;font-family:Arial,sans-serif;">Event details</p>
<table role="presentation" cellpadding="0" cellspacing="0" width="100%">
<tr><td style="width:40px;vertical-align:top;font-size:15px;color:#1A237E;">●</td><td style="font-size:17px;color:#1A237E;font-weight:bold;padding-bottom:12px;font-family:Georgia,serif;">${title}</td></tr>
<tr><td style="vertical-align:top;font-size:15px;color:#1A237E;">●</td><td style="font-size:15px;color:#444;padding-bottom:10px;font-family:Arial,sans-serif;"><strong style="color:#1A237E;">Date</strong><br/><span style="color:#333;">${date}</span></td></tr>
${timeRow}
<tr><td style="vertical-align:top;font-size:15px;color:#1A237E;">●</td><td style="font-size:15px;color:#444;font-family:Arial,sans-serif;"><strong style="color:#1A237E;">Venue</strong><br/><span style="color:#333;">${venue}</span></td></tr>
</table>
</td></tr>
</table>
<p style="margin:28px 0 0;font-size:14px;line-height:1.65;color:#555;font-family:Arial,sans-serif;border-top:1px solid #E8E0D4;padding-top:22px;">
Your <strong>formal invitation</strong> is attached as a <strong>PDF</strong> to this email. Please save it for your records.
</p>
<p style="margin:22px 0 0;font-size:12px;color:#9E9E9E;font-family:Arial,sans-serif;line-height:1.5;">With prayers and best wishes,</p>
<p style="margin:14px 0 0;font-size:14px;color:#C9A84C;font-weight:700;font-family:Arial,sans-serif;letter-spacing:0.3px;">BAPS Africa</p>
</td>
</tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

/**
 * @param {object} invite
 * @returns {Promise<Buffer>}
 */
function renderInvitationPdfBuffer(invite) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 0 });
    const chunks = [];
    doc.on("data", (c) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const pageW = doc.page.width;
    const margin = 48;
    const contentW = pageW - margin * 2;

    const headerH = logoBuffer ? 172 : 158;
    doc.rect(0, 0, pageW, headerH).fill("#1A237E");
    let hy = 12;
    if (logoBuffer) {
      try {
        const lw = 54;
        doc.image(logoBuffer, (pageW - lw) / 2, hy, { width: lw });
        hy = 70;
      } catch (_e) {
        hy = 32;
      }
    } else {
      hy = 32;
    }
    doc.fillColor("#C9A84C").font("Helvetica").fontSize(9).text("BAPS SWAMINARAYAN SANSTHA · AFRICA", margin, hy, {
      width: contentW,
      align: "center",
    });
    hy += 18;
    doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(22).text("PRASAR", margin, hy, { width: contentW, align: "center" });
    hy += 24;
    doc.fillColor("#d8dcf0").font("Helvetica").fontSize(8).text("Digital Outreach With A Devotional Heart.", margin, hy, {
      width: contentW,
      align: "center",
      lineGap: 2,
    });
    hy += doc.heightOfString("Digital Outreach With A Devotional Heart.", { width: contentW, lineGap: 2, align: "center" }) + 6;

    let y = headerH + 20;
    doc.fillColor("#1A237E").font("Helvetica-Bold").fontSize(10).text("To,", margin, y);
    y += 20;
    doc.fontSize(17).text(String(invite.dignitary_name || "Guest"), margin, y, { width: contentW });
    y += 28;
    const inviteLine = "The BAPS Swaminarayan Sanstha cordially invites you to grace the occasion of…";
    doc.fillColor("#333").fontSize(10).text(inviteLine, margin, y, { width: contentW, lineGap: 3 });
    y += doc.heightOfString(inviteLine, { width: contentW, lineGap: 3 }) + 16;
    const titleText = String(invite.event_title || "Event");
    doc.font("Helvetica-Bold").fontSize(19).fillColor("#1A237E");
    const titleH = doc.heightOfString(titleText, { width: contentW, align: "center" });
    doc.text(titleText, margin, y, { width: contentW, align: "center" });
    y += titleH + 22;

    const boxH = invite.event_time ? 108 : 88;
    doc.roundedRect(margin, y, contentW, boxH, 8).fillAndStroke("#FDF8F0", "#E0D8CC");
    const inner = margin + 18;
    let iy = y + 16;
    doc.font("Helvetica-Bold").fontSize(9).fillColor("#E8820C").text("EVENT DETAILS", inner, iy);
    iy += 20;
    doc.font("Helvetica").fontSize(11).fillColor("#333");
    doc.text(`Date: ${formatDateDisplay(invite.event_date)}`, inner, iy);
    iy += 18;
    if (invite.event_time) {
      doc.text(`Time: ${String(invite.event_time)}`, inner, iy);
      iy += 18;
    }
    doc.text(`Venue: ${String(invite.venue || "—")}`, inner, iy);
    y += boxH + 20;

    const bodyMsg = String(invite.custom_message || "").trim() || "You are cordially invited.";
    doc.font("Helvetica").fontSize(10).fillColor("#333").text(bodyMsg, margin, y, { width: contentW, lineGap: 4 });
    y += doc.heightOfString(bodyMsg, { width: contentW, lineGap: 4 }) + 28;

    doc.moveTo(margin, y).lineTo(pageW - margin, y).strokeColor("#E8E0D4").lineWidth(0.5).stroke();
    y += 14;
    doc.fontSize(8).fillColor("#888").text("Please retain this invitation for your records.", margin, y, {
      width: contentW,
      align: "center",
    });

    doc.end();
  });
}

module.exports = {
  escapeHtml,
  formatDateDisplay,
  buildInvitationEmailHtml,
  renderInvitationPdfBuffer,
};
