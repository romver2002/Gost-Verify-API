from io import BytesIO
from typing import Dict

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def register_fonts() -> tuple[str, str]:
    try:
        pdfmetrics.registerFont(TTFont('DejaVu', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
        pdfmetrics.registerFont(TTFont('DejaVu-Bold', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'))
        return 'DejaVu', 'DejaVu-Bold'
    except Exception:
        return 'Helvetica', 'Helvetica-Bold'


def _zwsp_wrap(s: str, step: int = 32) -> str:
    s = s or ""
    if not s:
        return s
    return "\u200b".join([s[i:i + step] for i in range(0, len(s), step)])


def build_pdf_report(ok: bool, details: Dict, pdf_name: str = 'doc.pdf', sig_name: str = 'doc.sig') -> bytes:
    base_font, bold_font = register_fonts()

    styles = getSampleStyleSheet()
    styles['Normal'].fontName = base_font
    styles['Normal'].fontSize = 10
    styles['Heading1'].fontName = bold_font
    styles['Heading1'].fontSize = 16
    styles['Heading1'].spaceAfter = 12
    pstyle = ParagraphStyle('P', parent=styles['Normal'], fontName=base_font, fontSize=10, leading=14, wordWrap='CJK')

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    elems = []
    elems.append(Paragraph("ПРОТОКОЛ ПРОВЕРКИ ЭЛЕКТРОННОЙ ПОДПИСИ", styles['Heading1']))

    # Документ №1
    mode = details.get('gost_mode', '') or ''
    head = [
        [Paragraph('<b>Документ №1</b>', styles['Normal'])],
        [Table([
            [Paragraph('Файл подписи (SIG):', pstyle), Paragraph(sig_name, pstyle)],
            [Paragraph('Исходный файл (PDF):', pstyle), Paragraph(pdf_name, pstyle)],
            [Paragraph(f'Хэш исходного файла (Streebog-{mode}):', pstyle), Paragraph(_zwsp_wrap((details.get('file_hash', '') or '').upper(), 32), pstyle)],
        ], colWidths=[160, 340])]
    ]
    head_tbl = Table(head, colWidths=[520])
    head_tbl.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 0.8, colors.black),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elems.append(head_tbl)
    elems.append(Spacer(1, 10))

    # Результат
    res_tbl = Table([
        [Paragraph('Результат проверки:', pstyle), Paragraph('<b><font color=green>Подпись действительна</font></b>' if ok else '<b><font color=red>Подпись недействительна</font></b>', pstyle)]
    ], colWidths=[160, 340])
    res_tbl.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 0.8, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E9F7EF') if ok else colors.HexColor('#FDECEA')),
    ]))
    elems.append(res_tbl)
    elems.append(Spacer(1, 10))

    # Сертификат
    subj = (details.get('subject', '') or '').replace('; ', ';<br/>')
    iss = (details.get('issuer', '') or '').replace('; ', ';<br/>')
    cert_tbl = Table([
        [Paragraph('<b>Сведения о сертификате подписи:</b>', pstyle), ''],
        [Paragraph('Субъект:', pstyle), Paragraph(subj, pstyle)],
        [Paragraph('Издатель:', pstyle), Paragraph(iss, pstyle)],
        [Paragraph('Действителен:', pstyle), Paragraph(f"с {details.get('not_before', '')} по {details.get('not_after', '')}", pstyle)],
        [Paragraph('Закрытый ключ действителен:', pstyle), Paragraph(f"с {details.get('not_before', '')} по {details.get('not_after', '')}", pstyle)],
        [Paragraph('Серийный номер:', pstyle), Paragraph(str(details.get('serial', '')), pstyle)],
        [Paragraph('Отпечаток:', pstyle), Paragraph(_zwsp_wrap(details.get('cert_thumb_sha256', '') or '', 32), pstyle)],
        [Paragraph('Режим ГОСТ:', pstyle), Paragraph(str(details.get('gost_mode', '') or ''), pstyle)],
        [Paragraph('Движок проверки:', pstyle), Paragraph(details.get('verify_engine', '') or '', pstyle)],
        [Paragraph('Кривая (pool key):', pstyle), Paragraph(details.get('curve_key', '') or '', pstyle)],
        [Paragraph('OID кривой:', pstyle), Paragraph(details.get('curve_oid', '') or '', pstyle)],
        [Paragraph('Вариант данных:', pstyle), Paragraph(details.get('data_variant', '') or '', pstyle)],
        [Paragraph('Вариант ключа:', pstyle), Paragraph(details.get('pub_variant', '') or '', pstyle)],
        [Paragraph('Вариант подписи:', pstyle), Paragraph(details.get('sig_variant', '') or '', pstyle)],
        [Paragraph('Доп. данные:', pstyle), Paragraph('', pstyle)],
        [Paragraph('Время подписи, полученное из штампа:', pstyle), Paragraph(details.get('signing_time', '') or '', pstyle)],
        [Paragraph('Время подписи:', pstyle), Paragraph(details.get('signing_time', '') or '', pstyle)],
        [Paragraph('Формат подписи:', pstyle), Paragraph(details.get('format', ''), pstyle)],
    ], colWidths=[220, 280])
    cert_tbl.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 0.8, colors.black),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('SPAN', (0, 0), (-1, 0)),
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elems.append(cert_tbl)

    doc.build(elems)
    return buf.getvalue()


