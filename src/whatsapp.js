/** Optional WhatsApp integration stub for deployments that expect this module. */
module.exports = {
  isConfigured() {
    return false;
  },
  async sendMessage() {
    return { ok: false, error: "WhatsApp is not configured." };
  },
};
