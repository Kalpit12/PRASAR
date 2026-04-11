/**
 * Postmark transactional email (same env pattern as AksharJobs).
 * https://postmarkapp.com/developer/api/email-api
 */

const https = require("https");

const POSTMARK_HOST = "api.postmarkapp.com";
const POSTMARK_PATH = "/email";

function cleanText(value, maxLen = 200) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/\s+/g, " ").slice(0, maxLen);
}

function isConfigured() {
  return Boolean(String(process.env.POSTMARK_API_KEY || "").trim());
}

function htmlToPlainText(html) {
  return String(html || "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * @param {object} opts
 * @param {string} opts.to
 * @param {string} opts.subject
 * @param {string} opts.htmlBody
 * @param {string} [opts.textBody]
 * @param {string} [opts.tag]
 * @param {{ name: string, contentBase64: string, contentType?: string }[]} [opts.attachments]
 * @returns {Promise<{ success: boolean, messageId?: string, error?: string, submittedAt?: string }>}
 */
async function sendEmail({ to, subject, htmlBody, textBody, tag, attachments }) {
  const token = String(process.env.POSTMARK_API_KEY || "").trim();
  if (!token) {
    return { success: false, error: "Postmark API key not configured" };
  }

  const senderEmail = cleanText(
    process.env.POSTMARK_SENDER_EMAIL || process.env.POSTMARK_FROM_EMAIL || "",
    200
  );
  const senderName = cleanText(process.env.POSTMARK_SENDER_NAME || "PRASAR", 120);
  const stream = cleanText(process.env.POSTMARK_MESSAGE_STREAM || "outbound", 64) || "outbound";
  const replyTo = cleanText(process.env.POSTMARK_REPLY_TO || "", 200);

  if (!senderEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(senderEmail)) {
    return { success: false, error: "POSTMARK_SENDER_EMAIL is missing or invalid" };
  }

  const payload = {
    From: `${senderName} <${senderEmail}>`,
    To: to,
    Subject: cleanText(subject, 998),
    HtmlBody: htmlBody,
    TextBody: textBody || htmlToPlainText(htmlBody),
    MessageStream: stream,
    TrackOpens: true,
  };

  if (replyTo && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(replyTo)) {
    payload.ReplyTo = replyTo;
  }
  if (tag) {
    payload.Tag = cleanText(tag, 100);
  }

  if (Array.isArray(attachments) && attachments.length) {
    payload.Attachments = attachments.map((a) => ({
      Name: cleanText(a.name || "attachment.pdf", 180),
      Content: String(a.contentBase64 || ""),
      ContentType: String(a.contentType || "application/octet-stream").trim().slice(0, 120) || "application/octet-stream",
    }));
  }

  const body = JSON.stringify(payload);

  try {
    const data = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: POSTMARK_HOST,
          port: 443,
          path: POSTMARK_PATH,
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body, "utf8"),
            "X-Postmark-Server-Token": token,
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            try {
              const raw = Buffer.concat(chunks).toString("utf8");
              resolve(JSON.parse(raw || "{}"));
            } catch (e) {
              reject(e);
            }
          });
        }
      );
      req.on("error", reject);
      req.write(body);
      req.end();
    });

    if (data.ErrorCode === 0) {
      return {
        success: true,
        messageId: data.MessageID,
        submittedAt: data.SubmittedAt,
      };
    }

    return {
      success: false,
      error: data.Message || "Postmark request failed",
    };
  } catch (e) {
    return { success: false, error: e.message || String(e) };
  }
}

module.exports = {
  isConfigured,
  sendEmail,
};
