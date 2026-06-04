from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal


DecisionAuthority = Literal["advisory_only"]


@dataclass(frozen=True)
class SparkDomainChip:
    """Specialist advisory profile that can be registered with Spark."""

    slug: str
    label: str
    domain: str
    agent_role: str
    decision_authority: DecisionAuthority
    purpose: str
    reputation_signals: tuple[str, ...]
    privacy_controls: tuple[str, ...]
    consent_requirements: tuple[str, ...]
    anti_bias_checks: tuple[str, ...]
    scoring_limits: tuple[str, ...]
    escalation_rules: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    output_contract: dict[str, str] = field(default_factory=dict)

    def to_registry_entry(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SparkRuntimeContextChip:
    """Specialist advisory profile for Spark runtime-support prompts."""

    slug: str
    label: str
    domain: str
    agent_role: str
    decision_authority: DecisionAuthority
    purpose: str
    trigger_phrases: tuple[str, ...]
    required_context_checks: tuple[str, ...]
    response_rules: tuple[str, ...]
    fallback_rules: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    output_contract: dict[str, str] = field(default_factory=dict)

    def to_registry_entry(self) -> dict[str, object]:
        return asdict(self)


SOCIAL_REPUTATION_CHIP = SparkDomainChip(
    slug="social-reputation-advisor",
    label="Social Reputation Advisor",
    domain="social_scoring",
    agent_role="specialist_advisory_agent",
    decision_authority="advisory_only",
    purpose=(
        "Evaluate opt-in social reputation signals and explain confidence, uncertainty, "
        "and safeguards for human review."
    ),
    reputation_signals=(
        "Verified account tenure, interaction consistency, and community contribution history.",
        "User-provided attestations, endorsements, and dispute outcomes with provenance.",
        "Policy-relevant integrity signals such as confirmed impersonation or spam patterns.",
        "Contextual recency and remediation evidence supplied by the evaluated person.",
    ),
    privacy_controls=(
        "Use data minimization: only process signals needed for the stated review purpose.",
        "Exclude private messages, sensitive personal data, and inferred protected traits.",
        "Keep provenance and retention metadata with every signal.",
        "Prefer aggregated or redacted evidence in summaries shown to reviewers.",
    ),
    consent_requirements=(
        "Require explicit opt-in before evaluating a person or importing third-party attestations.",
        "Show the person what signal categories are used before scoring.",
        "Allow consent withdrawal, correction requests, and appeal evidence.",
        "Separate consent for each new data source or materially different evaluation purpose.",
    ),
    anti_bias_checks=(
        "Do not use protected class, proxy, demographic, location, language, or disability signals.",
        "Run disparate-impact review before using a new signal source or weighting change.",
        "Compare adverse recommendations across cohorts where consented audit data exists.",
        "Down-rank signals with weak provenance, brigading risk, or cultural/context mismatch.",
    ),
    scoring_limits=(
        "Return bounded advisory bands rather than a universal person score.",
        "Attach confidence, missing-context notes, and evidence age to every recommendation.",
        "Do not rank people across unrelated communities or purposes.",
        "Do not recommend bans, removals, demotions, credit decisions, employment decisions, or law-enforcement actions.",
    ),
    escalation_rules=(
        "Escalate low-confidence, disputed, or high-impact cases to human review.",
        "Escalate suspected bias, consent gaps, or protected-trait leakage before presenting a score.",
        "Require reviewer confirmation before any platform policy action is considered.",
    ),
    prohibited_actions=(
        "Automated punitive decisions.",
        "Covert social scoring without notice and consent.",
        "Use of sensitive traits or proxies as reputation inputs.",
        "Permanent labels that cannot be appealed or corrected.",
    ),
    output_contract={
        "advisory_band": "low | medium | high | insufficient_context",
        "confidence": "0.0-1.0 with plain-language rationale",
        "evidence_summary": "brief provenance-aware explanation of included signals",
        "privacy_and_consent_status": "confirmed | missing | disputed",
        "anti_bias_status": "passed | needs_review | blocked",
        "limits": "clear statement that the result is advisory and non-punitive",
        "next_step": "human_review | request_more_context | no_action",
    },
)


RUNTIME_LOG_CONTEXT_CHIP = SparkRuntimeContextChip(
    slug="spark-runtime-log-context-advisor",
    label="Spark Runtime Log Context Advisor",
    domain="spark_runtime_support",
    agent_role="specialist_advisory_agent",
    decision_authority="advisory_only",
    purpose=(
        "Keep Spark support replies grounded in the user's requested artifact when they ask for "
        "run stdout, stderr, logs, diagnostics, or command output."
    ),
    trigger_phrases=(
        "show the Codex stdout/log for this run",
        "show stdout",
        "show stderr",
        "show logs",
        "show diagnostic notes",
        "what did this run output",
    ),
    required_context_checks=(
        "Identify the exact artifact the user requested before suggesting navigation.",
        "Check whether the requested artifact is stdout, stderr, application logs, or diagnostic notes.",
        "If the artifact is unavailable, say that directly and give the nearest exact command or path.",
        "Preserve the user's current surface and do not switch to Mission Control unless it owns the requested artifact.",
    ),
    response_rules=(
        "Answer with the requested stdout, stderr, log excerpt, command, or file path when available.",
        "When only a retrieval path is available, provide a concrete command such as `spark logs <service> --lines 80`.",
        "Separate Mission Control URLs from diagnostic-note locations so the user can tell which is relevant.",
        "State uncertainty when the run identifier, service name, or log source is missing.",
    ),
    fallback_rules=(
        "Ask for the run, service, or surface only when the missing value blocks retrieval.",
        "For Spawner UI failures, include `spark logs spawner-ui --lines 80` as the bounded smoke command.",
        "For diagnostic-agent work, mention `~/.spark/diagnostics` only as diagnostic notes, not as stdout.",
    ),
    prohibited_actions=(
        "Claim that a UI URL contains stdout/log output unless that is verified.",
        "Replace a stdout/log request with generic Mission Control onboarding guidance.",
        "Present diagnostic notes as the Codex stdout/log for the run.",
        "Invent log content or imply that unavailable logs were inspected.",
    ),
    output_contract={
        "requested_artifact": "stdout | stderr | service_log | diagnostic_notes | unknown",
        "artifact_status": "available | retrieval_path | missing_context | unavailable",
        "answer": "the excerpt, exact command, or exact path that matches the requested artifact",
        "context_boundary": "brief note distinguishing logs, diagnostics, and Mission Control UI",
        "next_step": "show_artifact | run_command | ask_for_context | open_ui",
    },
)


SparkRegistryChip = SparkDomainChip | SparkRuntimeContextChip


SPARK_DOMAIN_CHIPS: dict[str, SparkRegistryChip] = {
    SOCIAL_REPUTATION_CHIP.slug: SOCIAL_REPUTATION_CHIP,
    RUNTIME_LOG_CONTEXT_CHIP.slug: RUNTIME_LOG_CONTEXT_CHIP,
}


def get_spark_domain_chip(slug: str) -> SparkRegistryChip:
    return SPARK_DOMAIN_CHIPS[slug]
