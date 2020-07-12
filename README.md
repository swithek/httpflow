Barebones for common web applications:
- Root directory contains various request handling helpers (JSON decoding, errors with status codes, etc.)
- `user` package contains user auth/verification/recovery/etc. logic.
- `email` package contains email sending functionality (useful when using `user` package)

`cmd` directory contains a working example backed by postgres database.
