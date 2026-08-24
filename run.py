import os

from flask import request
from flask_webgoat import create_app

app = create_app()

ALLOWED_ORIGINS = set(
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000").split(",")
    if origin.strip()
)


@app.after_request
def add_security_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


if __name__ == "__main__":
    app.run()
