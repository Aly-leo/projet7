"""Service d'inférence de M1 (FastAPI).

Sécurité : entrées validées en mode strict (Pydantic), taille de requête et de lot bornées, jeton de service obligatoire
(M1_SERVICE_TOKEN, comparé en temps constant), écoute sur 127.0.0.1 par défaut, erreurs génériques, aucun chemin de
fichier choisi par l'appelant, aucun contenu sensible dans les journaux.
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from m1.common import MODELS
from m1.infer import M1Predictor

MAX_BATCH = 500
MAX_BODY_BYTES = 256 * 1024
log = logging.getLogger("m1.service")

Letter = Annotated[str, StringConstraints(pattern=r"^[A-Z]{1,3}$")]
CweStr = Annotated[str, StringConstraints(pattern=r"^(CWE-\d{1,5}|NVD-CWE-Other|NVD-CWE-noinfo|\d{1,5})$")]


class Features(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    cvss_base: float | None = Field(default=None, ge=0, le=10)
    av: Letter | None = None
    ac: Letter | None = None
    pr: Letter | None = None
    ui: Letter | None = None
    s: Letter | None = None
    c: Letter | None = None
    i: Letter | None = None
    a: Letter | None = None
    cwe: CweStr | None = None
    vendor_cve_count: int | None = Field(default=None, ge=0, le=10_000_000)
    exploitdb_before_t0: Literal[0, 1] | None = None


class Item(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    cveId: Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=30)] | None = None
    cweId: CweStr | None = None
    features: Features | None = None


class PredictRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    items: list[Item] = Field(min_length=1, max_length=MAX_BATCH)


class PredictionOut(BaseModel):
    probability: float
    source: Literal["m1", "cwe_rate", "prior"]
    modelVersion: str
    calibrated: bool
    alreadyInKev: bool | None = None
    relativeRisk: float | None = None  # probabilité / prévalence d'entraînement : 1 = risque moyen


class PredictResponse(BaseModel):
    predictions: list[PredictionOut]


def create_app(model_dir=MODELS, token: str | None = None) -> FastAPI:
    secret = token if token is not None else os.environ.get("M1_SERVICE_TOKEN", "")
    if len(secret) < 16:
        raise RuntimeError("M1_SERVICE_TOKEN absent ou trop court (16 caractères au moins) : le service refuse de démarrer.")
    predictor = M1Predictor(model_dir)
    app = FastAPI(title="M1 service", docs_url=None, redoc_url=None, openapi_url=None)  # pas de documentation exposée

    def auth(x_m1_token: Annotated[str | None, Header()] = None) -> None:
        if not x_m1_token or not hmac.compare_digest(x_m1_token.encode(), secret.encode()):
            raise HTTPException(status_code=401, detail="Non autorisé.")

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Requête trop volumineuse."}, status_code=413)
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, __: RequestValidationError):
        return JSONResponse({"detail": "Requête invalide."}, status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception):
        log.error("erreur interne : %s", type(exc).__name__)  # pas de contenu de requête dans les journaux
        return JSONResponse({"detail": "Erreur interne."}, status_code=500)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/model-info", dependencies=[Depends(auth)])
    def model_info() -> dict:
        return predictor.info()

    @app.post("/m1/predict", response_model=PredictResponse, dependencies=[Depends(auth)])
    def predict(req: PredictRequest) -> PredictResponse:
        items = [i.model_dump(exclude_none=True) for i in req.items]
        out = predictor.predict(items)
        return PredictResponse(predictions=[PredictionOut(probability=round(p.probability, 6), source=p.source, modelVersion=p.model_version,
                                                         calibrated=p.calibrated, alreadyInKev=p.already_in_kev,
                                                         relativeRisk=round(p.probability / predictor.prior, 3) if predictor.prior > 0 else None)
                                         for p in out])

    return app


def main() -> None:
    import uvicorn

    uvicorn.run(create_app(), host=os.environ.get("M1_HOST", "127.0.0.1"), port=int(os.environ.get("M1_PORT") or os.environ.get("PORT") or "8001"), log_level="warning")


if __name__ == "__main__":
    main()
