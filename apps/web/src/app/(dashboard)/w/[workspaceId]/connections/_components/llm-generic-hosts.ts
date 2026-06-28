const LLM_GENERIC_HOSTS = new Set([
  "api.deepseek.com",
  "api.groq.com",
  "api.moonshot.cn",
  "api.openrouter.ai",
  "generativelanguage.googleapis.com",
  "integrate.api.nvidia.com",
  "openrouter.ai",
]);

export const isGenericLlmHost = (hostPattern: string) =>
  LLM_GENERIC_HOSTS.has(hostPattern);
