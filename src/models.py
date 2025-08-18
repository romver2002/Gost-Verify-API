from pydantic import BaseModel, Field
from pydantic import ConfigDict
from typing import Optional, Dict, Union, Any


class VerificationError(BaseModel):
    error: str
    details: Optional[Dict[str, str]] = None


class VerificationSuccess(BaseModel):
    subject: str
    issuer: str
    serial: int
    gost_mode: int
    signing_time: Optional[str] = None
    file_hash: str
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    cert_thumb_sha256: Optional[str] = Field(None, alias="certThumbSha256")
    signature_type: str = "CMS"
    format: str = "Подпись в формате CAdES-T"
    verify_engine: str = "gostcrypto"
    curve_key: Optional[str] = None
    curve_oid: Optional[str] = None
    data_variant: str
    pub_variant: str
    sig_variant: str


class VerifyApiResponse(BaseModel):
    ok: bool
    details: Union[VerificationSuccess, VerificationError]


class DetectionResult(BaseModel):
    """Результат автоопределения параметров ГОСТ/кривой/ключа.

    Используется вместо кортежей для ясности и автодополнения.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    mode_bits: int
    curve: Any | None = None
    pub_bytes: bytes
    curve_key: Optional[str] = None
    curve_oid: Optional[str] = None
