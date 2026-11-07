"""GitHub App auth primitives and Checks API batching."""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import jwt

from app.config import get_settings
from app.github_app import GitHubApp, create_app_jwt, verify_webhook_signature
from tests.conftest import PRIVATE_PEM, PUBLIC_PEM


def test_webhook_signature() -> None:
    body = b'{"zen": "hi"}'
    good = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature("s3cret", body, good)
    assert not verify_webhook_signature("s3cret", body + b" ", good)
    assert not verify_webhook_signature("", body, good)  # fail closed without a secret
    assert not verify_webhook_signature("s3cret", body, None)


def test_app_jwt_claims() -> None:
    token = create_app_jwt("42", PRIVATE_PEM, now=1_700_000_000)
    claims = jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"],
                        options={"verify_exp": False})
    assert claims == {"iss": "42", "iat": 1_699_999_940, "exp": 1_700_000_480}


async def test_check_run_annotations_are_batched_by_50() -> None:
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={})

    annotations = [{"path": "a.py", "start_line": i, "end_line": i,
                    "annotation_level": "warning", "message": "m"} for i in range(1, 121)]
    async with GitHubApp(get_settings(), transport=httpx.MockTransport(handler)) as gh:
        await gh.complete_check_run("tok", "o", "r", 7, conclusion="failure", title="t",
                                    summary="s", annotations=annotations)
    assert [len(b["output"]["annotations"]) for b in sent] == [50, 50, 20]
    assert "conclusion" not in sent[0] and sent[-1]["conclusion"] == "failure"
    assert sent[-1]["status"] == "completed"
