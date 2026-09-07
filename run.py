from flask_webgoat import create_app

app = create_app()


@app.after_request
def add_security_headers(response):
    # Fix: Broken Access Control - restrict CORS to same origin
    response.headers['Access-Control-Allow-Origin'] = 'self'
    # Fix: Security Misconfiguration - strict CSP without unsafe-inline
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


if __name__ == '__main__':
    app.run(debug=False)
