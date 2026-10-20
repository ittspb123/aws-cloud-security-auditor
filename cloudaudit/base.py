"""Core abstractions: Severity, Finding, AuditContext and the Check base classes."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Iterable, Iterator

import boto3
from botocore.config import Config


class Severity(enum.IntEnum):
    """Higher value = more urgent. IntEnum so findings sort naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    cis_ref: str
    service: str
    resource: str
    region: str
    detail: str
    remediation: str
    evidence: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        """Identity used when comparing against an answer key."""
        return (self.check_id, self.resource)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


class AuditContext:
    """Holds the boto3 session, target regions and a client cache shared by all checks."""

    _RETRY = Config(retries={"max_attempts": 5, "mode": "adaptive"})

    def __init__(self, session: boto3.Session | None = None, regions: Iterable[str] | None = None):
        self.session = session or boto3.Session()
        self.regions = list(regions or [self.session.region_name or "us-east-1"])
        self._clients: dict[tuple[str, str], object] = {}
        self._account_id: str | None = None
        self.cache: dict = {}  # shared lookups (e.g. bucket list) so checks don't repeat API calls

    @property
    def home_region(self) -> str:
        return self.regions[0]

    def client(self, service: str, region: str | None = None):
        region = region or self.home_region
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=region, config=self._RETRY)
        return self._clients[key]

    @property
    def account_id(self) -> str:
        if self._account_id is None:
            self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id


class Check:
    """Base class for every check.

    Subclasses set the class attributes below and implement ``run``, yielding
    findings via ``self.finding(...)``. Subclasses are auto-registered.
    """

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    cis_ref: str = ""
    service: str = ""
    remediation: str = ""  # may contain {resource} / {region} placeholders

    registry: list[type["Check"]] = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.id:  # abstract intermediates (e.g. RegionalCheck) have no id
            Check.registry.append(cls)

    def run(self, ctx: AuditContext) -> Iterator[Finding]:
        raise NotImplementedError

    def finding(self, resource: str, detail: str, region: str = "global",
                severity: Severity | None = None, **evidence) -> Finding:
        return Finding(
            check_id=self.id,
            title=self.title,
            severity=severity if severity is not None else self.severity,
            cis_ref=self.cis_ref,
            service=self.service,
            resource=resource,
            region=region,
            detail=detail,
            remediation=self.remediation.format(resource=resource, region=region),
            evidence=evidence,
        )


class RegionalCheck(Check):
    """A check that is evaluated independently in every target region."""

    def run(self, ctx: AuditContext) -> Iterator[Finding]:
        for region in ctx.regions:
            yield from self.run_region(ctx, region)

    def run_region(self, ctx: AuditContext, region: str) -> Iterator[Finding]:
        raise NotImplementedError
