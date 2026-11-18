from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import PRODUCT_NAME, __version__
from .api import router
from .config import get_config
from .db import init_db
from .deps import client_ip
from .security import CSRF_COOKIE, SESSION_COOKIE, csrf_ok, new_csrf

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def frontend_dir() -> Path:
    env = os.environ.get("SCAKIT_FRONTEND_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _rate_limited(request: Request) -> int:
    import hashlib

    from . import ratelimit, settings_store
    try:
        limit = int(settings_store.cached("api_rate_per_minute") or 0)
    except ValueError:
        limit = 0
    if limit <= 0:
        return 0
    cred = request.cookies.get(SESSION_COOKIE) or request.headers.get("authorization", "")
    ident = hashlib.sha256(cred.encode()).hexdigest()[:24] if cred else f"ip:{client_ip(request)}"
    ok, wait = ratelimit.hit(f"api:{ident}", limit)
    return 0 if ok else wait


def create_app() -> FastAPI:
    init_db()
    app = FastAPI(title=PRODUCT_NAME, version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security(request: Request, call_next):
        path = request.url.path
        bearer = request.headers.get("authorization", "")[:7].lower() == "bearer "
        if path.startswith("/api/") and path not in ("/api/health", "/api/public/status"):
            limited = _rate_limited(request)
            if limited:
                return JSONResponse({"detail": f"Çok fazla istek; {limited} sn sonra tekrar deneyin"}, status_code=429,
                                    headers={"Retry-After": str(limited)})
        if path.startswith("/api/") and request.method in UNSAFE and not bearer:
            if not csrf_ok(request.cookies.get(CSRF_COOKIE), request.headers.get("X-CSRF-Token")):
                return JSONResponse({"detail": "CSRF doğrulaması başarısız; sayfayı yenileyin"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if CSRF_COOKIE not in request.cookies:
            response.set_cookie(CSRF_COOKIE, new_csrf(), httponly=False, samesite="strict",
                                secure=get_config().cookie_secure, path="/")
        return response

    app.include_router(router)
    from .messaging import router as messaging_router
    app.include_router(messaging_router)
    from .toolset import router as toolset_router
    app.include_router(toolset_router)
    from .capture import router as capture_router
    app.include_router(capture_router)

    from fastapi import Depends

    from .deps import current_user

    @app.get("/api/openapi.json", include_in_schema=False)
    def openapi_spec(_=Depends(current_user)):
        return app.openapi()

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    dist = frontend_dir()
    if (dist / "index.html").exists():
        if (dist / "assets").exists():
            app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/") or full_path == "deps.json":
                return JSONResponse({"detail": "Bulunamadı"}, status_code=404)
            f = (dist / full_path).resolve()
            if full_path and f.is_file() and str(f).startswith(str(dist.resolve())):
                return FileResponse(f)
            return FileResponse(dist / "index.html")
    return app
