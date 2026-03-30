FROM python:3.12-slim

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /pki

COPY generate_certs.sh /pki/
COPY serve_crl.py /pki/

RUN chmod +x /pki/generate_certs.sh && /pki/generate_certs.sh /pki/certs

EXPOSE 9999

CMD ["python", "/pki/serve_crl.py"]
