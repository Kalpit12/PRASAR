/**
 * WhatsApp Cloud API helper.
 * Docs: https://developers.facebook.com/docs/whatsapp/cloud-api/reference/messages
 */

const https = require("https");

function cleanText(value, maxLen = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/\s+/g, " ").slice(0, maxLen);
}

function normalizePhoneNumber(value) {
  let digits = String(value || "").replace(/[^\d+]/g, "");
  if (!digits) return "";
  if (digits.startsWith("+")) digits = digits.slice(1);
  if (digits.startsWith("00")) digits = digits.slice(2);
  digits = digits.replace(/\D/g, "");
  if (digits.length < 8 || digits.length > 15) return "";
  return digits;
}

function isConfigured() {
  const token = String(process.env.WHATSAPP_ACCESS_TOKEN || "").trim();
  const phoneNumberId = String(process.env.WHATSAPP_PHONE_NUMBER_ID || "").trim();
  return Boolean(token && phoneNumberId);
}

function buildWaMeLink(to, text) {
  const phone = normalizePhoneNumber(to);
  if (!phone) return "";
  const msg = cleanText(text || "", 3000);
  if (!msg) return `https://wa.me/${phone}`;
  return `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
}

/**
 * @param {object} opts
 * @param {string} opts.to
 * @param {string} opts.text
 * @returns {Promise<{ success: boolean, messageId?: string, error?: string, waMeLink?: string }>}
 */
async function sendText({ to, text }) {
  const token = String(process.env.WHATSAPP_ACCESS_TOKEN || "").trim();
  const phoneNumberId = String(process.env.WHATSAPP_PHONE_NUMBER_ID || "").trim();
  const apiVersion = cleanText(process.env.WHATSAPP_API_VERSION || "v22.0", 20) || "v22.0";

  const normalizedTo = normalizePhoneNumber(to);
  const messageText = cleanText(text || "", 4096);

  if (!token || !phoneNumberId) {
    return { success: false, error: "WhatsApp credentials are not configured", waMeLink: buildWaMeLink(to, text) };
  }
  if (!normalizedTo) {
    return { success: false, error: "Recipient phone number is missing or invalid" };
  }
  if (!messageText) {
    return { success: false, error: "Message text is empty" };
  }

  const payload = JSON.stringify({
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: normalizedTo,
    type: "text",
    text: {
      preview_url: false,
      body: messageText,
    },
  });

  const path = `/${apiVersion}/${encodeURIComponent(phoneNumberId)}/messages`;

  try {
    const data = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: "graph.facebook.com",
          port: 443,
          path,
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload, "utf8"),
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (chunk) => chunks.push(chunk));
          res.on("end", () => {
            try {
              const raw = Buffer.concat(chunks).toString("utf8");
              const parsed = JSON.parse(raw || "{}");
              resolve({ statusCode: res.statusCode || 500, body: parsed });
            } catch (error) {
              reject(error);
            }
          });
        }
      );
      req.on("error", reject);
      req.write(payload);
      req.end();
    });

    if (data.statusCode >= 200 && data.statusCode < 300 && Array.isArray(data.body?.messages) && data.body.messages[0]?.id) {
      return { success: true, messageId: data.body.messages[0].id };
    }

    const providerError =
      data.body?.error?.message ||
      data.body?.message ||
      `WhatsApp API request failed with status ${data.statusCode}`;

    return { success: false, error: providerError, waMeLink: buildWaMeLink(normalizedTo, messageText) };
  } catch (error) {
    return {
      success: false,
      error: error?.message || String(error),
      waMeLink: buildWaMeLink(normalizedTo, messageText),
    };
  }
}

module.exports = {
  isConfigured,
  sendText,
  buildWaMeLink,
  normalizePhoneNumber,
};
