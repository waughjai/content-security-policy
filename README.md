Content Security Policy
=========================

Class for easy generation o’ Content Security Policy header.

## Example

    use WaughJ\ContentSecurityPolicy\ContentSecurityPolicy;
    ContentSecurityPolicy::setPolicies
    ([
        'default-src' => [ "'self'" ],
        'style-src' => [ "'self'", "fonts.googleapis.com", "'unsafe-inline'" ],
        'script-src' => [ "'self'", "*.google-analytics.com", "*.googletagmanager.com", "'unsafe-inline'" ],
        'font-src' => [ "'self'", "fonts.gstatic.com" ],
        'img-src' => [ "'self'", "*.google-analytics.com" ],
        'script-src-elem' => [ "'self'", "*.google-analytics.com", "*.googletagmanager.com", "'unsafe-inline'" ]
    ]);

## Changelog

### 1.0.0
* Remake & simplify