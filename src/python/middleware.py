import asyncio
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from typing import Any, Callable, Dict, List, Optional

from engine import FingerprintEngine, InMemoryStore, RequestContext


class ASGIFingerprintMiddleware:
    """
    Universal ASGI 3.0 middleware. Compatible with FastAPI, Starlette, Quart, etc.
    """
    def __init__(self, app, security_config: Dict[str, Any], store: Optional[Any] = None):
        self.app = app
        self.store = store or InMemoryStore()
        self.engine = FingerprintEngine(security_config, self.store)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        client_ip = "127.0.0.1"
        if scope.get("client"):
            client_ip = scope["client"][0]
        xff = headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip()

        query_string = scope.get("query_string", b"").decode("latin1")
        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_string).items()}

        cookie_header = headers.get("cookie", "")
        cookies = {}
        if cookie_header:
            try:
                c = SimpleCookie()
                c.load(cookie_header)
                cookies = {k: v.value for k, v in c.items()}
            except Exception:
                pass

        context = RequestContext(
            client_ip=client_ip,
            path=scope.get("path", "/"),
            headers=headers,
            query_params=query_params,
            cookies=cookies,
            http_version=scope.get("http_version", "1.1"),
            scheme=scope.get("scheme", "http")
        )

        decision = await self.engine.process_request(context)

        if decision["action"] == "block":
            await self._send_response(send, decision.get("status", 403), [(b"content-type", b"text/plain")], decision.get("body", "Forbidden").encode("utf-8"))
            return

        if decision["action"] == "challenge":
            await self._send_response(send, decision.get("status", 403), [(b"content-type", b"text/html; charset=utf-8")], decision.get("body", "").encode("utf-8"))
            return

        if decision["action"] == "redirect":
            res_headers = [(b"location", decision["path"].encode("utf-8"))]
            if "cookie" in decision:
                c = decision["cookie"]
                cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                if c["options"].get("httponly"): cookie_val += "; HttpOnly"
                if c["options"].get("secure"): cookie_val += "; Secure"
                if c["options"].get("partitioned"): cookie_val += "; Partitioned"
                if "max_age" in c["options"]: cookie_val += f"; Max-Age={c['options']['max_age']}"
                res_headers.append((b"set-cookie", cookie_val.encode("utf-8")))
            await self._send_response(send, 302, res_headers, b"")
            return

        new_cookie = decision.get("newCookieForResponse")
        if new_cookie:
            async def custom_send(event):
                if event["type"] == "http.response.start":
                    c = new_cookie
                    cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                    if c["options"].get("httponly"): cookie_val += "; HttpOnly"
                    if c["options"].get("secure"): cookie_val += "; Secure"
                    if c["options"].get("partitioned"): cookie_val += "; Partitioned"
                    if "max_age" in c["options"]: cookie_val += f"; Max-Age={c['options']['max_age']}"
                    event["headers"].append((b"set-cookie", cookie_val.encode("utf-8")))
                await send(event)
            await self.app(scope, receive, custom_send)
        else:
            await self.app(scope, receive, send)

    async def _send_response(self, send, status: int, headers: List[tuple], body: bytes):
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})


class WSGIFingerprintMiddleware:
    """
    Universal WSGI 1.0 middleware. Compatible with Flask, Django, Bottle, etc.
    """
    def __init__(self, app, security_config: Dict[str, Any], store: Optional[Any] = None):
        self.app = app
        self.store = store or InMemoryStore()
        self.engine = FingerprintEngine(security_config, self.store)

    def __call__(self, environ, start_response):
        client_ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip() or environ.get("REMOTE_ADDR", "127.0.0.1")
        headers = {}
        for k, v in environ.items():
            if k.startswith("HTTP_"):
                headers[k[5:].replace("_", "-").lower()] = v
            elif k in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                headers[k.replace("_", "-").lower()] = v

        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
        cookies = {}
        cookie_header = headers.get("cookie", "")
        if cookie_header:
            try:
                c = SimpleCookie()
                c.load(cookie_header)
                cookies = {k: v.value for k, v in c.items()}
            except Exception:
                pass

        context = RequestContext(
            client_ip=client_ip,
            path=environ.get("PATH_INFO", "/"),
            headers=headers,
            query_params=query_params,
            cookies=cookies,
            http_version=environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
            scheme=environ.get("wsgi.url_scheme", "http")
        )

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        decision = loop.run_until_complete(self.engine.process_request(context))

        if decision["action"] == "block":
            start_response(f"{decision.get('status', 403)} Forbidden", [("Content-Type", "text/plain")])
            return [decision.get("body", "Forbidden").encode("utf-8")]

        if decision["action"] == "challenge":
            start_response(f"{decision.get('status', 403)} Forbidden", [("Content-Type", "text/html; charset=utf-8")])
            return [decision.get("body", "").encode("utf-8")]

        if decision["action"] == "redirect":
            res_headers = [("Location", decision["path"])]
            if "cookie" in decision:
                c = decision["cookie"]
                cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                if c["options"].get("httponly"): cookie_val += "; HttpOnly"
                if c["options"].get("secure"): cookie_val += "; Secure"
                if c["options"].get("partitioned"): cookie_val += "; Partitioned"
                if "max_age" in c["options"]: cookie_val += f"; Max-Age={c['options']['max_age']}"
                res_headers.append(("Set-Cookie", cookie_val))
            start_response("302 Found", res_headers)
            return [b""]

        return self.app(environ, start_response)


try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware

    class FastAPIFingerprintMiddleware(BaseHTTPMiddleware):
        """FastAPI-specific middleware."""
        def __init__(self, app, security_config: Dict[str, Any], store: Optional[InMemoryStore] = None):
            super().__init__(app)
            self.store = store or InMemoryStore()
            self.engine = FingerprintEngine(security_config, self.store)

        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            return await call_next(request)
except ImportError:
    pass