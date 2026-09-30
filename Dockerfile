FROM mitmproxy/mitmproxy:latest

WORKDIR /app
COPY smart_proxy.py /app/smart_proxy.py

EXPOSE 8080 1080

ENTRYPOINT ["mitmdump", "--mode", "regular@8080", "--mode", "socks5@1080", "-s", "/app/smart_proxy.py", "--set", "confdir=/ca", "--set", "connection_strategy=lazy", "--set", "upstream_cert=false", "--set", "block_global=false", "--set", "tcp_timeout=35"]
