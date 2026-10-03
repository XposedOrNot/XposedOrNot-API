 # Security Policy


## Reporting a Vulnerability

If you happen to discover 🔍 a bug or security vulnerability, I would love 😍 to hear from you! I encourage you to disclose it using the **[responsible disclosure](https://xposedornot.com/responsible-disclosure)** guidelines to support XposedOrNot.

You can report it via email at **deva @ xposedornot.com**.

I want to make it clear that this is not a bug bounty program and we do not offer a monetary reward for submissions. However, I would be happy to feature your valid submissions on our **[Hall of Fame](https://xposedornot.com/hof)** page, based on your preference. I believe in recognizing the positive contributions of reporters who have demonstrated a high level of dedication to our program.

## MCP Endpoint and Cross-Origin Access

The `/mcp` endpoint intentionally accepts requests from any Origin (CORS is `allow_origins=["*"]` with `allow_credentials=False`). Origin validation on MCP servers exists to stop DNS-rebinding attacks against privileged, typically localhost-bound servers. This endpoint is public, read-only, requires no authentication, and uses no cookies or sessions, so a restrictive Origin allowlist adds no protection here — it only breaks legitimate browser-based MCP clients. Abuse is mitigated by per-IP rate limiting on every MCP method and the underlying routes.
