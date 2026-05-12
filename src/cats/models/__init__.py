"""Pydantic v2 domain models.

These are the in-memory shapes used by agent code and the API. Database
schema lives in `cats.db.schema` and is intentionally separate; the two are
kept in sync by hand for now (we'll revisit if drift becomes a problem).
"""

from cats.models.attack import Attack, AttackSource
from cats.models.attack_execution import AttackExecution
from cats.models.audit import AuditLogEntry
from cats.models.campaign import Campaign, CampaignMode, CampaignTrigger
from cats.models.finding import Finding, Severity, Status
from cats.models.project import Project, ProjectEnv
from cats.models.project_version import ProjectVersion
from cats.models.regression import RegressionCase
from cats.models.report import VulnerabilityReport
from cats.models.rubric import RubricVersion
from cats.models.run import Run, RunStatus
from cats.models.verdict import Exploitability, JudgeVerdict, Verdict

__all__ = [
    "Attack",
    "AttackExecution",
    "AttackSource",
    "AuditLogEntry",
    "Campaign",
    "CampaignMode",
    "CampaignTrigger",
    "Exploitability",
    "Finding",
    "JudgeVerdict",
    "Project",
    "ProjectEnv",
    "ProjectVersion",
    "RegressionCase",
    "RubricVersion",
    "Run",
    "RunStatus",
    "Severity",
    "Status",
    "Verdict",
    "VulnerabilityReport",
]
