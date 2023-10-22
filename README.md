# https-mitm

An example for Man-in-the-Middle Proxy on HTTPS connection.

# Usage

```
cargo run
curl https://www.google.com --insecure -x http://localhost:3000
```

You can view the request and response in the console.