import os
import sys

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from cloudaudit.base import AuditContext  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def ctx(session):
    return AuditContext(session, [REGION])


def run(check_cls, ctx):
    return list(check_cls().run(ctx))


def resources(findings):
    return {f.resource for f in findings}
