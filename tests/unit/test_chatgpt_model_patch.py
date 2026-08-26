from __future__ import annotations

from squadrone.services import llm


def test_chatgpt_model_patches_clone_source_metadata(monkeypatch):
    fake_model_cost = {
        llm.CHATGPT_COMPAT_SOURCE_MODEL: {
            "litellm_provider": "chatgpt",
            "mode": "responses",
            "supports_function_calling": True,
        }
    }
    fake_chatgpt_models: list[str] = [llm.CHATGPT_COMPAT_SOURCE_MODEL]
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)
    monkeypatch.setattr(llm.litellm, "chatgpt_models", fake_chatgpt_models, raising=False)

    registered = llm._install_chatgpt_model_patches()

    assert registered == llm.CHATGPT_COMPAT_MODELS
    for target_model in llm.CHATGPT_COMPAT_MODELS:
        assert target_model in fake_model_cost
        assert fake_model_cost[target_model] is not fake_model_cost[llm.CHATGPT_COMPAT_SOURCE_MODEL]
        assert fake_model_cost[target_model]["litellm_provider"] == "chatgpt"
        assert fake_model_cost[target_model]["mode"] == "responses"
        assert target_model in fake_chatgpt_models


def test_chatgpt_model_patches_preserve_native_target(monkeypatch):
    existing_model = llm.CHATGPT_COMPAT_MODELS[0]
    target = {"litellm_provider": "chatgpt", "mode": "responses"}
    fake_model_cost = {
        llm.CHATGPT_COMPAT_SOURCE_MODEL: {"litellm_provider": "chatgpt", "mode": "responses"},
        existing_model: target,
    }
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)

    registered = llm._install_chatgpt_model_patches()

    assert registered == (llm.CHATGPT_COMPAT_MODELS[1],)
    assert fake_model_cost[existing_model] is target


def test_chatgpt_model_patches_noop_when_source_missing(monkeypatch):
    fake_model_cost = {}
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)

    registered = llm._install_chatgpt_model_patches()

    assert registered == ()
    assert not any(model in fake_model_cost for model in llm.CHATGPT_COMPAT_MODELS)
