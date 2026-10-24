
import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.schemas import PROFILE, CommitRequest, ProposeRequest
from app.service import (
    RequestValidationError,
    ServiceConflictError,
    ServiceProcessingError,
    process_commit,
    process_propose,
)


app = FastAPI(
    title="Mailroom Action Gate",
    version="2.0.0",
)

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 512 * 1024


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/")
async def mailroom_endpoint(request: Request):
    content_length = request.headers.get("content-length")

    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Request body too large",
                )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="Invalid Content-Length",
            ) from exc

    body = await request.body()

    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Request body too large",
        )

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON",
        ) from exc

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=422,
            detail="Request must be a JSON object",
        )

    try:
        operation = data.get("operation")

        if operation == "propose":
            ProposeRequest.model_validate_json(body)
            result = process_propose(data)

        elif operation == "commit":
            CommitRequest.model_validate_json(body)
            result = process_commit(data)

        else:
            raise HTTPException(
                status_code=400,
                detail="Unsupported operation",
            )

        response = JSONResponse(
            status_code=200,
            content=result,
        )

        if len(response.body) > MAX_RESPONSE_BYTES:
            raise HTTPException(
                status_code=500,
                detail="Successful response exceeds the permitted size",
            )

        return response

    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_input=False),
        ) from exc

    except RequestValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    except ServiceConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except ServiceProcessingError as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to process the proposal safely",
        ) from exc
