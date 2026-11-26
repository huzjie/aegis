"""Small text utilities (slugify + Chinese-aware tokenization)."""

import re

_WS = re.compile(r"\s+")
_NONWORD = re.compile(r"[^\w\u4e00-\u9fff]+")


def slugify(text: str, sep: str = "-") -> str:
    """Lowercase, strip punctuation, collapse whitespace to *sep*."""
    t = _WS.sub(" ", text.strip().lower())
    t = _NONWORD.sub(" ", t)
    return sep.join(part for part in t.split(" ") if part)


def tokenize_cn(text: str, bigram: bool = True) -> list:
    """Naive Chinese-aware tokenizer.

    Splits on non-CJK/non-alnum boundaries, keeping CJK characters as
    individual tokens or overlapping bigrams. Good enough for keyword /
    signature matching without any external tokenizer dependency.
    """
    text = text.lower()
    # segment into runs of CJK vs latin/digit
    runs = re.findall(r"[\u4e00-\u9fff]+|[a-z0-9_]+", text)
    tokens = []
    for run in runs:
        if re.match(r"[a-z0-9_]+", run):
            tokens.append(run)
            continue
        if bigram and len(run) >= 2:
            tokens.extend(run[i:i + 2] for i in range(len(run) - 1))
        else:
            tokens.extend(run)
    return tokens


def normalize(text: str) -> str:
    return _WS.sub(" ", text.strip())
