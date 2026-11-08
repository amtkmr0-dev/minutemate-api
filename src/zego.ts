/** Server-only media configuration. Never return the signing secret to clients. */
export function getZegoConfig(env: NodeJS.ProcessEnv = process.env) {
  const rawAppId = env.ZEGO_APP_ID ?? "";
  const appId = Number(rawAppId);
  const serverSecret = env.ZEGO_SERVER_SECRET ?? "";
  if (!/^\d+$/.test(rawAppId) || !Number.isSafeInteger(appId) || appId <= 0
    || serverSecret.length !== 32 || Buffer.byteLength(serverSecret, "utf8") !== 32) return null;

  const serverUrl = env.ZEGO_SERVER_URL || `wss://webliveroom${appId}-api.zegocloud.com/ws`;
  try {
    const url = new URL(serverUrl);
    if (url.protocol !== "wss:" || !url.hostname || url.username || url.password || url.hash) return null;
  } catch {
    return null;
  }
  return { appId, serverSecret, serverUrl };
}
