from squadrone.agents.prompts_io import load_prompt


def test_program_reports_preserve_second_order_sql_lifecycle() -> None:
    for prompt_name in ("reporter_patchstack", "reporter_wordfence"):
        prompt = load_prompt(prompt_name)
        assert "injection_order" in prompt
        assert "storage_boundary" in prompt
        assert "attacker" in prompt and "trigger" in prompt


def test_program_reports_do_not_treat_impact_label_as_runtime_proof() -> None:
    for prompt_name in ("reporter_patchstack", "reporter_wordfence"):
        prompt = load_prompt(prompt_name)
        assert "impact_labels" in prompt
        assert "metadata" in prompt
        assert "confirmation" in prompt


def test_program_reports_keep_root_cause_classification_when_rce_is_impact() -> None:
    for prompt_name in ("reporter_patchstack", "reporter_wordfence"):
        prompt = load_prompt(prompt_name)
        assert "root-cause" in prompt
        assert "root_cause_cwe" in prompt
        assert "CWE-434" in prompt
        assert "Arbitrary File Upload" in prompt
        assert "reclassif" in prompt or "never replace" in prompt
