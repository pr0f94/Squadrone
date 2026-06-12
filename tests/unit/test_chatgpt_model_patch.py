from __future__ import annotations

from squadrone.services import llm


def test_chatgpt_55_patch_clones_54_metadata(monkeypatch):
    fake_model_cost = {
        llm.CHATGPT_55_SOURCE_MODEL: {
            "litellm_provider": "chatgpt",
            "mode": "responses",
            "supports_function_calling": True,
        }
    }
    fake_chatgpt_models: list[str] = [llm.CHATGPT_55_SOURCE_MODEL]
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)
    monkeypatch.setattr(llm.litellm, "chatgpt_models", fake_chatgpt_models, raising=False)

    applied = llm._install_chatgpt_55_model_patch()

    assert applied is True
    assert llm.CHATGPT_55_MODEL in fake_model_cost
    assert fake_model_cost[llm.CHATGPT_55_MODEL] is not fake_model_cost[llm.CHATGPT_55_SOURCE_MODEL]
    assert fake_model_cost[llm.CHATGPT_55_MODEL]["litellm_provider"] == "chatgpt"
    assert fake_model_cost[llm.CHATGPT_55_MODEL]["mode"] == "responses"
    assert llm.CHATGPT_55_MODEL in fake_chatgpt_models


def test_chatgpt_55_patch_noops_when_target_exists(monkeypatch):
    target = {"litellm_provider": "chatgpt", "mode": "responses"}
    fake_model_cost = {
        llm.CHATGPT_55_SOURCE_MODEL: {"litellm_provider": "chatgpt", "mode": "responses"},
        llm.CHATGPT_55_MODEL: target,
    }
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)

    applied = llm._install_chatgpt_55_model_patch()

    assert applied is False
    assert fake_model_cost[llm.CHATGPT_55_MODEL] is target


def test_chatgpt_55_patch_noops_when_source_missing(monkeypatch):
    fake_model_cost = {}
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)

    applied = llm._install_chatgpt_55_model_patch()

    assert applied is False
    assert llm.CHATGPT_55_MODEL not in fake_model_cost
