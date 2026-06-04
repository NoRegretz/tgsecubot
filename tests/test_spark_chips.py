from security_bot.spark_chips import (
    RUNTIME_LOG_CONTEXT_CHIP,
    SOCIAL_REPUTATION_CHIP,
    get_spark_domain_chip,
)


def test_social_reputation_chip_registers_as_specialist_advisory_agent():
    chip = get_spark_domain_chip("social-reputation-advisor")

    assert chip is SOCIAL_REPUTATION_CHIP
    assert chip.domain == "social_scoring"
    assert chip.agent_role == "specialist_advisory_agent"
    assert chip.decision_authority == "advisory_only"


def test_social_reputation_chip_blocks_automated_punitive_decisions():
    prohibited = " ".join(SOCIAL_REPUTATION_CHIP.prohibited_actions).casefold()
    limits = " ".join(SOCIAL_REPUTATION_CHIP.scoring_limits).casefold()

    assert "automated punitive decisions" in prohibited
    assert "bans" in limits
    assert "removals" in limits
    assert "employment decisions" in limits
    assert "law-enforcement actions" in limits


def test_social_reputation_chip_requires_privacy_consent_and_anti_bias_controls():
    consent = " ".join(SOCIAL_REPUTATION_CHIP.consent_requirements).casefold()
    privacy = " ".join(SOCIAL_REPUTATION_CHIP.privacy_controls).casefold()
    anti_bias = " ".join(SOCIAL_REPUTATION_CHIP.anti_bias_checks).casefold()

    assert "explicit opt-in" in consent
    assert "consent withdrawal" in consent
    assert "data minimization" in privacy
    assert "sensitive personal data" in privacy
    assert "protected class" in anti_bias
    assert "disparate-impact review" in anti_bias


def test_social_reputation_chip_registry_entry_is_serializable():
    entry = SOCIAL_REPUTATION_CHIP.to_registry_entry()

    assert entry["slug"] == "social-reputation-advisor"
    assert entry["output_contract"]["advisory_band"] == "low | medium | high | insufficient_context"


def test_runtime_log_context_chip_registers_as_spark_support_advisor():
    chip = get_spark_domain_chip("spark-runtime-log-context-advisor")

    assert chip is RUNTIME_LOG_CONTEXT_CHIP
    assert chip.domain == "spark_runtime_support"
    assert chip.agent_role == "specialist_advisory_agent"
    assert chip.decision_authority == "advisory_only"


def test_runtime_log_context_chip_triggers_on_stdout_log_requests():
    triggers = " ".join(RUNTIME_LOG_CONTEXT_CHIP.trigger_phrases).casefold()
    checks = " ".join(RUNTIME_LOG_CONTEXT_CHIP.required_context_checks).casefold()
    contract = RUNTIME_LOG_CONTEXT_CHIP.output_contract

    assert "show the codex stdout/log for this run" in triggers
    assert "show stdout" in triggers
    assert "show logs" in triggers
    assert "requested artifact" in checks
    assert contract["requested_artifact"] == "stdout | stderr | service_log | diagnostic_notes | unknown"


def test_runtime_log_context_chip_prevents_mission_control_substitution():
    rules = " ".join(RUNTIME_LOG_CONTEXT_CHIP.response_rules).casefold()
    fallback = " ".join(RUNTIME_LOG_CONTEXT_CHIP.fallback_rules).casefold()
    prohibited = " ".join(RUNTIME_LOG_CONTEXT_CHIP.prohibited_actions).casefold()

    assert "separate mission control urls from diagnostic-note locations" in rules
    assert "spark logs spawner-ui --lines 80" in fallback
    assert "mission control onboarding guidance" in prohibited
    assert "present diagnostic notes as the codex stdout/log" in prohibited
    assert "invent log content" in prohibited
