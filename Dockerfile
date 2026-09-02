FROM mitmproxy/mitmproxy:latest

WORKDIR /app
COPY smart_proxy.py /app/smart_proxy.py

EXPOSE 8080

ENTRYPOINT ["mitmdump", "-p", "8080", "-s", "/app/smart_proxy.py", "--set", "confdir=/ca", "--set", "connection_strategy=lazy", "--set", "upstream_cert=false", "--set", "block_global=false", "--set", "tcp_timeout=10"]
