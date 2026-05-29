# Deployment Notes

- Application root: `/opt/oplogica-verify-demo`
- Public URL: `https://oplogica.com/ova-demo/`
- systemd unit: `ova-demo.service`
- Service state: active and enabled
- Local bind: `127.0.0.1:8000`
- Nginx strips the `/ova-demo` prefix and proxies to the FastAPI app.
- `/exports` is served with `no-store` and is intentionally public for demo
  reproducibility.

## Known limitation

`POST /verify` is unauthenticated and unrate-limited. This is acceptable for a
public proof-of-concept demo, but it must be revisited before heavier exposure
or any production-style deployment.
