from binary_agent.utils import env as env_utils


def test_load_dotenv_if_available_returns_false_when_dependency_missing(monkeypatch) -> None:
    monkeypatch.setattr(env_utils, "_load_dotenv", None)

    assert env_utils.load_dotenv_if_available() is False


def test_load_dotenv_if_available_delegates_to_loader(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_loader(*args, **kwargs) -> bool:
        called["args"] = args
        called["kwargs"] = kwargs
        return True

    monkeypatch.setattr(env_utils, "_load_dotenv", fake_loader)

    assert env_utils.load_dotenv_if_available(dotenv_path="test.env") is True
    assert called == {"args": (), "kwargs": {"dotenv_path": "test.env"}}
