from __future__ import annotations

import litellm

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
    assert "chatgpt/gpt-daybreak-blue-latest" in registered
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

    assert registered == tuple(
        model for model in llm.CHATGPT_COMPAT_MODELS if model != existing_model
    )
    assert fake_model_cost[existing_model] is target


def test_chatgpt_model_patches_noop_when_source_missing(monkeypatch):
    fake_model_cost = {}
    monkeypatch.setattr(llm.litellm, "model_cost", fake_model_cost)

    registered = llm._install_chatgpt_model_patches()

    assert registered == ()
    assert not any(model in fake_model_cost for model in llm.CHATGPT_COMPAT_MODELS)


def test_chatgpt_compat_aliases_use_gpt5_parameter_family():
    from litellm.llms.openai.chat.gpt_5_transformation import OpenAIGPT5Config

    for model in llm.CHATGPT_COMPAT_MODELS:
        assert OpenAIGPT5Config.is_model_gpt_5_model(model)

    # The extension must not widen unrelated or non-reasoning model families.
    assert not OpenAIGPT5Config.is_model_gpt_5_model("gpt-4o")
    assert not OpenAIGPT5Config.is_model_gpt_5_model("gpt-5-chat-latest")


def test_daybreak_accepts_reasoning_effort_before_provider_dispatch():
    supported = litellm.get_supported_openai_params(
        model="gpt-daybreak-blue-latest",
        custom_llm_provider="chatgpt",
    )
    assert supported is not None
    assert "reasoning_effort" in supported

    optional = litellm.get_optional_params(
        model="gpt-daybreak-blue-latest",
        custom_llm_provider="chatgpt",
        reasoning_effort="medium",
        max_tokens=64,
    )
    assert optional["reasoning_effort"] == "medium"
    assert optional["max_completion_tokens"] == 64
