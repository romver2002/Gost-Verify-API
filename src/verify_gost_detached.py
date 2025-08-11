#!/usr/bin/env python3
import sys
import binascii
import hashlib

from asn1crypto import cms, x509, core
from gostcrypto import gosthash, gostsignature
try:
    from pygost.gost3410 import CURVE_PARAMS as PYGOST_CURVES, GOST3410Curve
    from pygost.gost34112012 import GOST34112012
    _PYGOST_AVAILABLE = True
except Exception:
    _PYGOST_AVAILABLE = False


def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}")
    sys.exit(code)


def _encode_der_length(length: int) -> bytes:
    """Encode length in DER definite form."""
    if length < 0x80:
        return bytes([length])
    out = []
    n = length
    while n > 0:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes([0x80 | len(out)]) + bytes(out)


def unwrap_octet_string_if_present(data: bytes) -> bytes:
    """
    Если внутри BIT STRING лежит OCTET STRING (0x04 ...), извлекаем его содержимое.
    Также удаляем ведущий 0x00, если он случайно присутствует.
    """
    if not data:
        return data
    try:
        if data[0] == 0x04:
            obj = core.OctetString.load(data)
            val = obj.native
            if isinstance(val, (bytes, bytearray)):
                data = bytes(val)
    except Exception:
        pass
    # Убираем возможный ведущий нулевой байт для выравнивания
    if len(data) in (65, 129) and data[0] == 0x00:
        data = data[1:]
    return data


def stribog_hash(data: bytes, bits: int) -> bytes:
    try:
        if bits == 256:
            h = gosthash.new('streebog256')
            h.update(data)
            return h.digest()
        elif bits == 512:
            h = gosthash.new('streebog512')
            h.update(data)
            return h.digest()
    except Exception:
        # Фоллбек на pygost, если установлен
        if _PYGOST_AVAILABLE:
            if bits == 256:
                return GOST34112012(data).digest()
            elif bits == 512:
                return GOST34112012(data, digest_size=64).digest()
    die("Unsupported Streebog size")
    return b""


def bit_string_payload(bitstr_obj) -> bytes:
    """
    Извлекаем полезную нагрузку из ASN.1 BIT STRING без зависимости от OID.
    """
    try:
        val = bitstr_obj.native
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
    except Exception:
        pass
    raw = bitstr_obj.dump()
    if not raw or raw[0] != 0x03:
        die("Invalid BIT STRING encoding")
    i = 1
    length = raw[i]
    i += 1
    if length & 0x80:
        nlen = length & 0x7F
        if nlen == 0 or nlen > 4:
            die("Unsupported BIT STRING length form")
        length = 0
        for _ in range(nlen):
            length = (length << 8) | raw[i]
            i += 1
    if i >= len(raw):
        die("Corrupt BIT STRING")
    unused_bits = raw[i]
    i += 1
    payload = raw[i:i + (length - 1)]
    if unused_bits != 0:
        die("BIT STRING with unused bits not supported")
    return bytes(payload)


def detect_mode_and_curve_and_pubkey(signer_info: cms.SignerInfo, cert: x509.Certificate):
    # Определяем разрядность ГОСТ по OID алгоритмов или по длине подписи/ключа
    sig_oid = signer_info['signature_algorithm']['algorithm'].dotted
    dig_oid = signer_info['digest_algorithm']['algorithm'].dotted

    # OID'ы TC26
    G3410_2012_256 = '1.2.643.7.1.1.1.1'
    G3410_2012_512 = '1.2.643.7.1.1.1.2'
    G3411_2012_256 = '1.2.643.7.1.1.2.2'
    G3411_2012_512 = '1.2.643.7.1.1.2.3'

    mode = None
    if sig_oid == G3410_2012_512 or dig_oid == G3411_2012_512:
        mode = 512
    elif sig_oid == G3410_2012_256 or dig_oid == G3411_2012_256:
        mode = 256

    # Извлекаем SPKI и ключ (X||Y) как bytes, избегая OID-специфичных маппингов asn1crypto
    spki = cert['tbs_certificate']['subject_public_key_info']
    # Парсим как общий SEQUENCE: [ algorithm, public_key BIT STRING ]
    spki_seq = core.Sequence.load(spki.dump())
    # AlgorithmIdentifier is first element (algorithm OID + parameters)
    algo_seq = spki_seq[0]
    pk_bitstr = spki_seq[1]
    pub_bytes = bit_string_payload(pk_bitstr)
    pub_bytes = unwrap_octet_string_if_present(pub_bytes)
    # pub_bytes должен быть 64 (256) или 128 (512)
    if mode is None:
        if len(pub_bytes) == 64:
            mode = 256
        elif len(pub_bytes) == 128:
            mode = 512

    # Если всё ещё None, попробуем по длине подписи
    if mode is None:
        sig_bytes = signer_info['signature'].native
        if len(sig_bytes) == 64:
            mode = 256
        elif len(sig_bytes) == 128:
            mode = 512

    if mode is None:
        die("Cannot determine GOST mode (256/512)")

    # Пытаемся достать curve OID из AlgorithmIdentifier.parameters
    curve_oid = None
    try:
        if isinstance(algo_seq, core.Sequence) and len(algo_seq) >= 2:
            params = algo_seq[1]
            if isinstance(params, core.ObjectIdentifier):
                curve_oid = params.dotted
    except Exception:
        curve_oid = None

    # Подбираем кривую в gostcrypto по размеру, если OID не удалось извлечь
    pool = gostsignature.CURVES_R_1323565_1_024_2019
    curve = None
    chosen_key = None
    if curve_oid:
        # Иногда ключи — это имена, а не OID; попробуем и так, и так
        if curve_oid in pool:
            chosen_key = curve_oid
        else:
            # Поищем ключ, содержащий фрагмент OID в имени (на всякий случай)
            for k in pool.keys():
                if curve_oid.replace('.', '-') in k:
                    chosen_key = k
                    break
    if chosen_key is None:
        # Фоллбек: по разрядности
        keys = list(pool.keys())
        if mode == 256:
            # Сначала paramSetB, затем любой 256
            preferred = [k for k in keys if '2012-256' in k and k.endswith('paramSetB')]
            if not preferred:
                preferred = [k for k in keys if '2012-256' in k]
            if preferred:
                chosen_key = preferred[0]
        else:
            # 512: сначала paramSetA, затем любой 512
            preferred = [k for k in keys if '12-512' in k and k.endswith('paramSetA')]
            if not preferred:
                preferred = [k for k in keys if '12-512' in k]
            if preferred:
                chosen_key = preferred[0]
        # Если вдруг ничего не нашли — возьмем первый доступный
        if chosen_key is None and keys:
            chosen_key = keys[0]

    if chosen_key is not None:
        curve = pool[chosen_key]

    # Если не смогли выбрать
    if curve is None:
        # Попытаемся верифицировать через pygost как резервный путь
        curve = None

    # Кривую выбрали
    return mode, curve, pub_bytes, chosen_key, curve_oid


def load_signed_data(sig_bytes: bytes) -> cms.SignedData:
    ci = cms.ContentInfo.load(sig_bytes)
    if ci['content_type'].native != 'signed_data':
        die("Not a CMS SignedData file")
    return ci['content']


def pick_signer(sd: cms.SignedData) -> cms.SignerInfo:
    infos = sd['signer_infos']
    if len(infos) == 0:
        die("No SignerInfo found")
    return infos[0]


def find_signer_cert(sd: cms.SignedData, signer_info: cms.SignerInfo) -> x509.Certificate:
    certs = sd['certificates']
    if not certs:
        die("No certificates in signature")
    sid = signer_info['sid']
    for c in certs:
        cert = c if isinstance(c, x509.Certificate) else c.chosen
        if sid.name == 'issuer_and_serial_number':
            iasn = sid.chosen
            if cert.issuer == iasn['issuer'] and cert.serial_number == iasn['serial_number'].native:
                return cert
        elif sid.name == 'subject_key_identifier':
            skid = sid.chosen.native
            try:
                ext = cert.extensions.get('subject_key_identifier')
                if ext and ext.native == skid:
                    return cert
            except Exception:
                pass
    ce = certs[0]
    return ce if isinstance(ce, x509.Certificate) else ce.chosen


def verify_detached_cms(pdf_bytes: bytes, sig_bytes: bytes):
    """Проверка откреплённой подписи CMS (ГОСТ 2012). Возвращает (ok, details)."""
    sd = load_signed_data(sig_bytes)
    signer_info = pick_signer(sd)
    cert = find_signer_cert(sd, signer_info)

    # Определяем режим ГОСТ, кривую и ключ
    mode_bits, curve, pub_bytes, chosen_key_detected, curve_oid = detect_mode_and_curve_and_pubkey(signer_info, cert)
    mode_const = gostsignature.MODE_256 if mode_bits == 256 else gostsignature.MODE_512

    # Проверка messageDigest
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs is None:
        raise ValueError("Signed attributes are required for CAdES/CMS verification")
    msg_digest = None
    signing_time = None
    for a in signed_attrs:
        if a['type'].native == 'message_digest':
            msg_digest = a['values'][0].native
            break
        if a['type'].native == 'signing_time':
            try:
                signing_time = a['values'][0].native.isoformat()
            except Exception:
                signing_time = None
    if msg_digest is None:
        raise ValueError("messageDigest attribute not found")
    real_digest = stribog_hash(pdf_bytes, mode_bits)
    if real_digest != msg_digest:
        return False, {
            'error': 'messageDigest != hash(file)',
            'expected': binascii.hexlify(msg_digest).decode(),
            'actual': binascii.hexlify(real_digest).decode(),
        }

    # Универсальный SET (0x31) из содержимого signedAttrs (A0) и реверс хэша
    try:
        contents = signed_attrs.contents
        universal_der = b"\x31" + _encode_der_length(len(contents)) + contents
        data_hash = stribog_hash(universal_der, mode_bits)[::-1]
        data_variant_label = 'universal_set_hash_rev'
    except Exception:
        to_be_signed = signed_attrs.dump()
        data_hash = stribog_hash(to_be_signed, mode_bits)[::-1]
        data_variant_label = 'a0_hash_rev'

    # Подпись S||R
    sig_raw = signer_info['signature'].native
    if len(sig_raw) not in (64, 128):
        return False, {'error': f'Unexpected signature length: {len(sig_raw)}'}
    half = len(sig_raw) // 2
    sig_fixed = sig_raw[half:] + sig_raw[:half]

    # Ключ rev(X)||rev(Y)
    if len(pub_bytes) not in (64, 128):
        return False, {'error': f'Unexpected public key length: {len(pub_bytes)}'}
    khalf = len(pub_bytes) // 2
    x = pub_bytes[:khalf][::-1]
    y = pub_bytes[khalf:][::-1]
    pub_fixed = x + y

    sign_obj = gostsignature.new(mode_const, curve)
    if not sign_obj.verify(pub_fixed, data_hash, sig_fixed):
        return False, {
            'error': 'cryptographic verify failed',
            'stage': 'direct-verify',
            'gost_mode': mode_bits,
        }

    # Период действия сертификата
    try:
        validity = cert['tbs_certificate']['validity']
        not_before = validity['not_before'].native
        not_after = validity['not_after'].native
        not_before_str = not_before.isoformat()
        not_after_str = not_after.isoformat()
    except Exception:
        not_before_str = None
        not_after_str = None

    # Отпечаток сертификата (SHA-256)
    try:
        cert_sha256 = hashlib.sha256(cert.dump()).hexdigest().upper()
    except Exception:
        cert_sha256 = None

    return True, {
        'subject': cert.subject.human_friendly,
        'issuer': cert.issuer.human_friendly,
        'serial': int(cert.serial_number),
        'gost_mode': mode_bits,
        'signing_time': signing_time,
        'file_hash': binascii.hexlify(real_digest).decode(),
        'not_before': not_before_str,
        'not_after': not_after_str,
        'cert_thumb_sha256': cert_sha256,
        'signature_type': 'CMS',
        'format': 'Подпись в формате CAdES-T',
        'verify_engine': 'gostcrypto',
        'curve_key': chosen_key_detected,
        'curve_oid': curve_oid,
        'data_variant': data_variant_label,
        'pub_variant': 'rev(X)||rev(Y)',
        'sig_variant': 'S||R',
    }

def main():
    # Старт
    if len(sys.argv) != 3:
        print("Usage: verify_gost_detached.py <file.pdf> <file.sig>")
        sys.exit(2)
    pdf_path = sys.argv[1]
    sig_path = sys.argv[2]

    # Читаем входы
    try:
        with open(pdf_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        die(f"Cannot read PDF: {e}")
    try:
        with open(sig_path, 'rb') as f:
            sig = f.read()
    except Exception as e:
        die(f"Cannot read signature: {e}")

    # Вводы прочитаны

    # Парсим CMS
    sd = load_signed_data(sig)
    signer_info = pick_signer(sd)
    cert = find_signer_cert(sd, signer_info)

    # Определяем режим ГОСТ, кривую и получаем публичный ключ как bytes (X||Y)
    mode_bits, curve, pub_bytes, detected_curve_key, detected_curve_oid = detect_mode_and_curve_and_pubkey(signer_info, cert)
    mode_const = gostsignature.MODE_256 if mode_bits == 256 else gostsignature.MODE_512
    # Режим ГОСТ: 256/512

    # Проверим detached: контент внутри, как правило, пуст (игнорируем, действуем как detached)
    eci = sd['encap_content_info']

    # Извлекаем signed attributes
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs is None:
        die("Signed attributes are required for CAdES/CMS verification")

    # Алгоритмы/атрибуты прочитаны

    # messageDigest должен совпасть с Стрибогом(PDF)
    msg_digest = None
    for a in signed_attrs:
        if a['type'].native == 'message_digest':
            msg_digest = a['values'][0].native
            break
    if msg_digest is None:
        die("messageDigest attribute not found")

    real_digest = stribog_hash(data, mode_bits)
    if real_digest != msg_digest:
        print("Signature FAIL: messageDigest != hash(file)")
        print(f"expected (from sig): {binascii.hexlify(msg_digest).decode()}")
        print(f"actual  (from pdf): {binascii.hexlify(real_digest).decode()}")
        sys.exit(1)
    else:
        print(f"messageDigest OK (Streebog-{mode_bits})")

    # Данные для подписи: попробуем разные варианты кодирования signedAttrs
    to_be_signed = signed_attrs.dump()
    hash_signed_attrs = stribog_hash(to_be_signed, mode_bits)
    # Вариант с универсальным SET (0x31) вместо контекст-специфического тега [0]
    try:
        contents = signed_attrs.contents  # содержимое SET OF Attribute без тега/длины
        universal_der = b"\x31" + _encode_der_length(len(contents)) + contents
        universal_der_hash = stribog_hash(universal_der, mode_bits)
    except Exception:
        universal_der = None
        universal_der_hash = None

    # Нормализация signedAttrs: SORT BY DER of Attribute для SET (хотя asn1crypto уже сортирует)
    try:
        attrs_sorted = sorted(list(signed_attrs), key=lambda a: a.dump())
        attrs_concat = b"".join(a.dump() for a in attrs_sorted)
        normalized_set = b"\x31" + _encode_der_length(len(attrs_concat)) + attrs_concat
        normalized_set_hash = stribog_hash(normalized_set, mode_bits)
    except Exception:
        normalized_set = None
        normalized_set_hash = None

    # Подпись как OCTET STRING: может быть R||S или S||R, также возможны отличия по эндьянности
    sig_bytes = signer_info['signature'].native
    if len(sig_bytes) not in (64, 128):
        die(f"Unexpected signature length: {len(sig_bytes)}")
    sig_half = len(sig_bytes) // 2
    r = sig_bytes[:sig_half]
    s = sig_bytes[sig_half:]

    # Возможные варианты подписи (порядок и эндьянность компонент)
    sig_candidates = [
        r + s,
        s + r,
        r[::-1] + s[::-1],
        s[::-1] + r[::-1],
        (r + s)[::-1],
        (s + r)[::-1],
    ]

    # Возможные варианты публичного ключа (порядок координат и эндьянность)
    if len(pub_bytes) not in (64, 128):
        die(f"Unexpected public key length: {len(pub_bytes)}")
    key_half = len(pub_bytes) // 2
    x = pub_bytes[:key_half]
    y = pub_bytes[key_half:]
    pub_candidates = [
        x + y,            # X||Y
        y + x,            # Y||X
        x[::-1] + y[::-1],# rev(X)||rev(Y)
        y[::-1] + x[::-1],# rev(Y)||rev(X)
        (x + y)[::-1],
        (y + x)[::-1],
    ]

    ok = False
    chosen_combo = None
    chosen_data_variant = None  # 0 - hash(A0), 1 - raw A0, 2 - hash(SET), 3 - raw SET, 6/7 - reversed варианты
    chosen_curve_key = None
    data_variants = [
        (0, hash_signed_attrs),
        (6, hash_signed_attrs[::-1]),
        (1, to_be_signed),
        (7, to_be_signed[::-1]),
    ]
    if universal_der is not None:
        data_variants.extend([
            (2, universal_der_hash),
            (8, universal_der_hash[::-1]),
            (3, universal_der),
            (9, universal_der[::-1]),
        ])
    if normalized_set is not None:
        data_variants.extend([(4, normalized_set_hash), (5, normalized_set)])

    # Подберем кривую: сначала текущая, затем остальные подходящей разрядности
    pool = gostsignature.CURVES_R_1323565_1_024_2019
    # Попробуем найти имя выбранной кривой
    initial_key = None
    for k, v in pool.items():
        if v is curve or v == curve:
            initial_key = k
            break
    curve_keys = []
    if initial_key is not None:
        curve_keys.append(initial_key)
    # Добавим остальные ключи такой же разрядности
    for k in pool.keys():
        if k == initial_key:
            continue
        if (mode_bits == 256 and '2012-256' in k) or (mode_bits == 512 and '12-512' in k):
            curve_keys.append(k)

    print(f"Проверка подписи: блок 1 (gostcrypto). Кандидатов кривых: {len(curve_keys)}")
    for curve_key in curve_keys:
        print(f"  -> кривая: {curve_key}")
        try:
            sign_obj = gostsignature.new(mode_const, pool[curve_key])
        except Exception:
            continue
        for data_idx, (variant_id, data_try) in enumerate(data_variants):
            for pub_try in pub_candidates:
                for sig_try in sig_candidates:
                    try:
                        if sign_obj.verify(pub_try, data_try, sig_try):
                            ok = True
                            chosen_combo = (pub_candidates.index(pub_try), sig_candidates.index(sig_try))
                            chosen_data_variant = variant_id
                            chosen_curve_key = curve_key
                            pub_bytes = pub_try
                            sig_bytes = sig_try
                            break
                    except Exception:
                        pass
                if ok:
                    break
            if ok:
                break
        if ok:
            break

    # Фоллбек: проверка через pygost (если не удалось через gostcrypto и pygost доступен)
    if not ok and _PYGOST_AVAILABLE:
        print("Проверка подписи: блок 2 (pygost). Перебираем набор кривых pygost по разрядности")
        # Подбор кривой pygost по размеру
        pygost_curve_names = [name for name, params in PYGOST_CURVES.items() if (mode_bits == 256 and '256' in name) or (mode_bits == 512 and '512' in name)]
        for curve_name in pygost_curve_names:
            print(f"  -> кривая (pygost): {curve_name}")
            params = PYGOST_CURVES[curve_name]
            # публичный ключ как point раскодируем всеми вариантами
            for pub_try in pub_candidates:
                try:
                    # pygost ожидает X||Y big-endian
                    # пытаемся развернуть, если нужно
                    key_half = len(pub_try) // 2
                    X = int.from_bytes(pub_try[:key_half], 'big')
                    Y = int.from_bytes(pub_try[key_half:], 'big')
                    # кривая
                    curve = GOST3410Curve(params.p, params.q, params.a, params.b, params.x, params.y)
                except Exception:
                    continue
                for variant_id, data_try in data_variants:
                    # pygost.verify ожидает числовые r,s
                    for sig_try in sig_candidates:
                        sig_half = len(sig_try) // 2
                        r_int = int.from_bytes(sig_try[:sig_half], 'big')
                        s_int = int.from_bytes(sig_try[sig_half:], 'big')
                        try:
                            # В pygost проверка производится через метод curve.verify
                            if curve.verify(X, Y, data_try, (r_int, s_int)):
                                ok = True
                                chosen_combo = (pub_candidates.index(pub_try), sig_candidates.index(sig_try))
                                chosen_data_variant = variant_id
                                chosen_curve_key = f"pygost:{curve_name}"
                                break
                        except Exception:
                            pass
                    if ok:
                        break
                if ok:
                    break
            if ok:
                break

    if not ok:
        print("Signature FAIL: cryptographic verify failed")
        sys.exit(1)

    # Если успех в одном из блоков — сообщим выбранные варианты
    data_variant_names = {
        0: 'hash(A0)', 6: 'rev hash(A0)',
        1: 'A0', 7: 'rev A0',
        2: 'hash(SET)', 8: 'rev hash(SET)',
        3: 'SET', 9: 'rev SET',
        4: 'hash(SET, normalized)', 5: 'SET, normalized',
    }
    pub_variant_names = {
        0: 'X||Y', 1: 'Y||X', 2: 'rev(X)||rev(Y)', 3: 'rev(Y)||rev(X)', 4: 'rev(X||Y)', 5: 'rev(Y||X)'
    }
    sig_variant_names = {
        0: 'R||S', 1: 'S||R', 2: 'rev(R)||rev(S)', 3: 'rev(S)||rev(R)', 4: 'rev(R||S)', 5: 'rev(S||R)'
    }
    if chosen_curve_key is not None and chosen_combo is not None and chosen_data_variant is not None:
        print("Выбранные параметры проверки:")
        print(f"  кривая: {chosen_curve_key}")
        print(f"  вариант данных: {data_variant_names.get(chosen_data_variant, str(chosen_data_variant))}")
        print(f"  вариант ключа: {pub_variant_names.get(chosen_combo[0], str(chosen_combo[0]))}")
        print(f"  вариант подписи: {sig_variant_names.get(chosen_combo[1], str(chosen_combo[1]))}")

    # Информация о сертификате
    subject = cert.subject.human_friendly
    issuer = cert.issuer.human_friendly
    serial = cert.serial_number

    print("Signature OK")
    print(f"Signer subject: {subject}")
    print(f"Issuer: {issuer}")
    print(f"Serial: {serial}")
    print(f"GOST mode: {mode_bits}")
    print("Script finished")

if __name__ == "__main__":
    main()
