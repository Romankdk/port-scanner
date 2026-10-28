"""Text helpers shared by every module that displays data received from the network."""


def clean(text: str) -> str:
    """Drop control characters so hostile network data can't inject terminal escape sequences."""
    return "".join(ch for ch in text if ch.isprintable())
