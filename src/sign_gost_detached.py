import binascii
import datetime
import secrets
from typing import Tuple

from asn1crypto import cms, x509, core, pkcs12
from asn1crypto.keys import PrivateKeyInfo
from gostcrypto import gostsignature

# Повторно используем утилиты из верификатора, чтобы обеспечить совместимость
from verify_gost_detached import _encode_der_length, stribog_hash, bit_string_payload, unwrap_octet_string_if_present
from models import DetectionResult


def _pem_to_der(maybe_pem: bytes) -> bytes:
    """Преобразовать PEM (если это PEM) в DER. Если уже DER — вернуть как есть."""
    data = maybe_pem.strip()
    if data.startswith(b"-----BEGIN"):
        lines = [l.strip() for l in data.splitlines() if b"-----" not in l]
        return binascii.a2b_base64(b"".join(lines))
    return data


def _detect_mode_and_curve_by_cert(cert: x509.Certificate) -> DetectionResult:
    """Определяем режим ГОСТ (256/512) и кривую gostcrypto из сертификата.

    Возвращает кортеж: (mode_bits, curve_obj, curve_oid)
    """
    # Извлекаем SPKI и ключ (X||Y) как bytes, избегая OID-специфичных маппингов asn1crypto
    spki = cert['tbs_certificate']['subject_public_key_info']
    spki_seq = core.Sequence.load(spki.dump())
    algo_seq = spki_seq[0]
    pk_bitstr = spki_seq[1]

    # Получаем длину ключа, чтобы определить режим
    pub_bytes = bit_string_payload(pk_bitstr)
    pub_bytes = unwrap_octet_string_if_present(pub_bytes)

    if len(pub_bytes) == 64:
        mode_bits = 256
    elif len(pub_bytes) == 128:
        mode_bits = 512
    else:
        raise ValueError("Неизвестная длина публичного ключа в сертификате")

    # Попробуем достать OID кривой из AlgorithmIdentifier.parameters
    curve_oid = None
    try:
        if isinstance(algo_seq, core.Sequence) and len(algo_seq) >= 2:
            params = algo_seq[1]
            if isinstance(params, core.ObjectIdentifier):
                curve_oid = params.dotted
    except Exception:
        curve_oid = None

    # Подбираем кривую в gostcrypto по разрядности
    pool = gostsignature.CURVES_R_1323565_1_024_2019
    curve_key_name = None
    keys = list(pool.keys())
    if curve_oid:
        if curve_oid in pool:
            curve_key_name = curve_oid
        else:
            for k in keys:
                if curve_oid.replace('.', '-') in k:
                    curve_key_name = k
                    break
    if curve_key_name is None:
        if mode_bits == 256:
            preferred = [k for k in keys if '2012-256' in k and k.endswith('paramSetB')]
            if not preferred:
                preferred = [k for k in keys if '2012-256' in k]
            if preferred:
                curve_key_name = preferred[0]
        else:
            preferred = [k for k in keys if '12-512' in k and k.endswith('paramSetA')]
            if not preferred:
                preferred = [k for k in keys if '12-512' in k]
            if preferred:
                curve_key_name = preferred[0]
        if curve_key_name is None and keys:
            curve_key_name = keys[0]

    curve = pool[curve_key_name]
    return DetectionResult(mode_bits=mode_bits, curve=curve, pub_bytes=pub_bytes, curve_key=curve_key_name, curve_oid=curve_oid)


def create_detached_cms(pdf_bytes: bytes, cert_bytes: bytes, private_key_hex: str) -> bytes:
    """
    Создать откреплённую подпись CMS (CAdES) для файла.

    Вход:
      - pdf_bytes: содержимое исходного файла
      - cert_bytes: сертификат X.509 в DER/PEM
      - private_key_hex: приватный ключ (скаляр d) в hex (big-endian)

    Выход: байтовый массив CMS SignedData (detached), пригодный для сохранения как .sig
    """
    cert_der = _pem_to_der(cert_bytes)
    cert = x509.Certificate.load(cert_der)

    # Режим, кривая и публичный ключ из сертификата
    det = _detect_mode_and_curve_by_cert(cert)
    mode_bits = det.mode_bits
    curve = det.curve
    pub_bytes = det.pub_bytes
    mode_const = gostsignature.MODE_256 if mode_bits == 256 else gostsignature.MODE_512

    # Алгоритмы ГОСТ ОИД
    G3410_2012_256 = '1.2.643.7.1.1.1.1'
    G3410_2012_512 = '1.2.643.7.1.1.1.2'
    G3411_2012_256 = '1.2.643.7.1.1.2.2'
    G3411_2012_512 = '1.2.643.7.1.1.2.3'
    sig_oid = G3410_2012_512 if mode_bits == 512 else G3410_2012_256
    dig_oid = G3411_2012_512 if mode_bits == 512 else G3411_2012_256

    # Подготовка signedAttrs
    file_digest = stribog_hash(pdf_bytes, mode_bits)
    signing_time = datetime.datetime.utcnow()
    attrs = [
        cms.CMSAttribute({'type': 'content_type', 'values': ['data']}),
        cms.CMSAttribute({'type': 'signing_time', 'values': [signing_time]}),
        cms.CMSAttribute({'type': 'message_digest', 'values': [file_digest]}),
    ]
    signed_attrs = cms.CMSAttributes(attrs)

    # Дайджест данных для подписи: универсальный SET и реверс (как в верификаторе)
    contents = signed_attrs.contents
    universal_der = b"\x31" + _encode_der_length(len(contents)) + contents
    data_hash = stribog_hash(universal_der, mode_bits)[::-1]

    # Подпись данных
    sign_obj = gostsignature.new(mode_const, curve)
    d_bytes = binascii.unhexlify(private_key_hex.strip())
    sig_bytes = sign_obj.sign(d_bytes, data_hash)

    # Получаем публичный ключ из сертификата для самопроверки формата подписи
    # Версия, совместимая с verify: pub_fixed = rev(X)||rev(Y)
    if len(pub_bytes) not in (64, 128):
        raise ValueError("Неожиданная длина публичного ключа")
    khalf = len(pub_bytes) // 2
    x = pub_bytes[:khalf][::-1]
    y = pub_bytes[khalf:][::-1]
    pub_fixed = x + y

    def swap_halves(b: bytes) -> bytes:
        h = len(b) // 2
        return b[h:] + b[:h]

    # Проверим, какой вариант понимает verify-движок сейчас
    cms_sig_candidate = None
    try:
        if sign_obj.verify(pub_fixed, data_hash, sig_bytes):
            # verify ожидает R||S, значит CMS должен содержать S||R
            cms_sig_candidate = swap_halves(sig_bytes)
        elif sign_obj.verify(pub_fixed, data_hash, swap_halves(sig_bytes)):
            # verify ожидает S||R, значит CMS должен содержать R||S
            cms_sig_candidate = sig_bytes
        else:
            raise ValueError("Подпись не верифицируется ни в одном из форматов")
    except Exception:
        # Если verify выбросил исключение, попробуем второй вариант
        if sign_obj.verify(pub_fixed, data_hash, swap_halves(sig_bytes)):
            cms_sig_candidate = sig_bytes
        else:
            raise

    # SignerInfo (issuerAndSerialNumber)
    sid = cms.SignerIdentifier({'issuer_and_serial_number': cms.IssuerAndSerialNumber({
        'issuer': cert.issuer,
        'serial_number': cert.serial_number,
    })})

    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': sid,
        'digest_algorithm': {'algorithm': dig_oid},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': sig_oid},
        'signature': core.OctetString(cms_sig_candidate),
        # unsigned_attrs можно добавить позднее (штампы времени и т. п.)
    })

    sd = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [cms.DigestAlgorithm({'algorithm': dig_oid})],
        'encap_content_info': {'content_type': 'data'},  # detached: content отсутствует
        'certificates': [cert],
        'signer_infos': [signer_info],
    })

    ci = cms.ContentInfo({'content_type': 'signed_data', 'content': sd})
    return ci.dump()


def create_detached_cms_from_pfx(pdf_bytes: bytes, pfx_bytes: bytes, password: str | None = None) -> bytes:
    """
    Создать откреплённую подпись из PKCS#12 (PFX).

    Ограничения реализации:
      - Поддерживается только KeyBag (незашифрованный приватный ключ в PFX)
      - ShroudedKeyBag (зашифрованный приватный ключ) не поддержан в этой сборке
    """
    pfx = pkcs12.Pfx.load(pfx_bytes)
    auth_safe = pfx['auth_safe']
    # ContentInfo с типом data → OctetString с сериализованным SafeContents
    ci = auth_safe
    if ci['content_type'].native != 'data':
        raise ValueError('PFX: unsupported content type (not data)')
    data = ci['content'].native  # bytes DER SafeContents
    safe = pkcs12.SafeContents.load(data)

    priv_hex = None
    cert_der = None
    for bag in safe:
        bag_id = bag['bag_id'].native
        if bag_id == 'keyBag':
            pki = bag['bag_value'].chosen  # PrivateKeyInfo
            if not isinstance(pki, PrivateKeyInfo):
                continue
            # Для ГОСТ приватный ключ обычно лежит как OCTET STRING внутри private_key
            pk = pki['private_key'].native
            if isinstance(pk, (bytes, bytearray)):
                priv_hex = binascii.hexlify(bytes(pk)).decode()
        elif bag_id == 'certBag':
            cert_chosen = bag['bag_value'].chosen
            if cert_chosen.name == 'x509_certificate':
                cert_der = cert_chosen.chosen.dump()

    if not priv_hex:
        raise ValueError('PFX: приватный ключ не найден в незашифрованном виде (KeyBag). ShroudedKeyBag не поддержан в этой сборке.')
    if not cert_der:
        raise ValueError('PFX: сертификат не найден в certBag')

    return create_detached_cms(pdf_bytes, cert_der, priv_hex)


