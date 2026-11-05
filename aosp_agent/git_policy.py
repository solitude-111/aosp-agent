"""Git transport policy inherited by child Git processes, including old lazy fetch."""
import os


OFFLINE_GIT_ENV = {
    "GIT_ALLOW_PROTOCOL": "",  # overrides protocol.<name>.allow and survives child Git
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
}


def offline_git_env(base=None):
    return dict(os.environ if base is None else base, **OFFLINE_GIT_ENV)
