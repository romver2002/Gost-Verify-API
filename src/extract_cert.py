#!/usr/bin/env python3
"""
Извлечение сертификата из CMS/CAdES подписи (.sig) и вывод в PEM.

Использование (в Docker):
  - Вывести PEM в stdout и сохранить на хосте:
    docker compose run -T --rm gost-verify python extract_cert.py /data/doc.sig > samples/cert.pem

Опции:
  --der   — вывести сертификат в DER как base64 (без PEM-обёртки),
            удобно сохранять через PowerShell Set-Content -Encoding Byte.
"""

import sys
import base64
from typing import Optional

from asn1crypto import x509, cms

from verify_gost_detached import load_signed_data, pick_signer, find_signer_cert


def to_pem(tag: str, der: bytes) -> str:
    """Преобразовать DER в PEM (строка)."""
    b64 = base64.encodebytes(der).decode('ascii')
    b64 = ''.join(b64.splitlines())
    lines = [f"-----BEGIN {tag}-----"]
    # Разбиваем по 64 символов на строку
    for i in range(0, len(b64), 64):
        lines.append(b64[i:i + 64])
    lines.append(f"-----END {tag}-----")
    return '\n'.join(lines) + '\n'


def extract_cert_der(sig_path: str) -> bytes:
    """Извлечь DER сертификата подписанта из файла подписи."""
    data = open(sig_path, 'rb').read()
    sd = load_signed_data(data)
    si = pick_signer(sd)
    cert = find_signer_cert(sd, si)
    assert isinstance(cert, x509.Certificate)
    return cert.dump()


def main(argv: list[str]) -> None:
    if len(argv) < 2 or argv[1] in ('-h', '--help'):
        print("Usage: extract_cert.py <file.sig> [--der]", file=sys.stderr)
        sys.exit(2)
    sig_path = argv[1]
    as_der = ('--der' in argv)

    der = extract_cert_der(sig_path)
    if as_der:
        # Для удобства в PowerShell можно сохранить так:
        # docker compose run -T --rm gost-verify python extract_cert.py /data/doc.sig --der | \
        #   Set-Content -Encoding Byte samples/cert.cer
        sys.stdout.buffer.write(der)
    else:
        pem = to_pem('CERTIFICATE', der)
        sys.stdout.write(pem)


if __name__ == '__main__':
    main(sys.argv)


