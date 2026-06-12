"""
Three-layer Injection Gate for the Dual-LLM Analyst Pipeline.

Layers
------
1. **Regex check** -- fast pattern matching against known injection signatures.
2. **Heuristic check** -- statistical analysis (entropy, char-class ratios,
   length anomalies).
3. **LLM check** (optional) -- uses a dedicated LLM call to evaluate the
   content for adversarial manipulation.

The gate combines scores from all layers and decides whether to ``allow``,
``quarantine``, or ``block`` the content before it reaches the Fact Extractor.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from typing import TYPE_CHECKING, List, Optional

from soc_analyst.agents.analyst.schemas import InjectionCheckResult
from soc_analyst.agents.analyst.prompts import INJECTION_CHECK_PROMPT

if TYPE_CHECKING:
    from soc_analyst.agents.llm_router import LLMRouter

logger = logging.getLogger(__name__)

__all__ = ["InjectionGate"]


# ---------------------------------------------------------------------------
# Known injection patterns (Layer 1)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction_override", re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?)",
        re.IGNORECASE,
    )),
    ("instruction_override", re.compile(
        r"disregard\s+(your|all|any)\s+(rules?|instructions?|guidelines?)",
        re.IGNORECASE,
    )),
    ("role_manipulation", re.compile(
        r"you\s+are\s+now\s+a", re.IGNORECASE
    )),
    ("role_manipulation", re.compile(
        r"act\s+as\s+(if\s+you\s+are|a|an)\s+", re.IGNORECASE
    )),
    ("role_manipulation", re.compile(
        r"new\s+(instructions?|role|persona|identity)", re.IGNORECASE
    )),
    ("encoded_payload", re.compile(
        r"[A-Za-z0-9+/]{40,}={0,2}", re.ASCII  # Base64 blobs
    )),
    ("data_exfiltration", re.compile(
        r"(reveal|show|print|output|display|leak)\s+(your\s+)?(system\s+prompt|instructions|api\s*key|secret)",
        re.IGNORECASE,
    )),
    ("command_injection", re.compile(
        r"\b(eval|exec|system|subprocess|os\.popen|import\s+os)\s*\(",
        re.IGNORECASE,
    )),
    ("delimiter_attack", re.compile(
        r"<\s*/?\s*(system|instruction|prompt|user|assistant)\s*>",
        re.IGNORECASE,
    )),
    ("social_engineering", re.compile(
        r"(this\s+is\s+an?\s+emergency|urgent|do\s+not\s+question|trust\s+me|I\s+am\s+your\s+(admin|creator|developer))",
        re.IGNORECASE,
    )),
    ("prompt_leak", re.compile(
        r"(repeat|echo|print)\s+(everything|all|the\s+text)\s+(above|before|so\s+far)",
        re.IGNORECASE,
    )),
]


# ---------------------------------------------------------------------------
# Injection Gate
# ---------------------------------------------------------------------------

class InjectionGate:
    """Multi-layer prompt-injection detector.

    Usage::

        gate = InjectionGate()
        result = await gate.check(content, llm=optional_router)
    """

    # Thresholds
    BLOCK_THRESHOLD: float = 0.7
    QUARANTINE_THRESHOLD: float = 0.4

    # Heuristic limits
    MAX_SAFE_LENGTH: int = 10_000
    HIGH_ENTROPY_THRESHOLD: float = 5.5  # bits per character

    # Layer weights for combining scores
    WEIGHT_REGEX: float = 0.45
    WEIGHT_HEURISTIC: float = 0.25
    WEIGHT_LLM: float = 0.30

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(
        self,
        content: str,
        llm: Optional["LLMRouter"] = None,
    ) -> InjectionCheckResult:
        """Run all injection-detection layers and return a combined result.

        Parameters
        ----------
        content:
            Raw alert content to inspect.
        llm:
            Optional LLM router for the third (LLM-based) layer.

        Returns
        -------
        InjectionCheckResult
        """
        regex_result = self._regex_check(content)
        heuristic_result = self._heuristic_check(content)

        if llm is not None:
            llm_result = await self._llm_check(content, llm)
        else:
            llm_result = InjectionCheckResult(
                is_suspicious=False,
                risk_score=0.0,
                detected_patterns=[],
                sanitized_content=content,
                action="allow",
            )

        # Combine scores (weighted average)
        if llm is not None:
            combined_score = (
                self.WEIGHT_REGEX * regex_result.risk_score
                + self.WEIGHT_HEURISTIC * heuristic_result.risk_score
                + self.WEIGHT_LLM * llm_result.risk_score
            )
        else:
            # Without LLM layer, re-normalise weights
            total = self.WEIGHT_REGEX + self.WEIGHT_HEURISTIC
            combined_score = (
                (self.WEIGHT_REGEX / total) * regex_result.risk_score
                + (self.WEIGHT_HEURISTIC / total) * heuristic_result.risk_score
            )

        # Merge detected patterns
        all_patterns: List[str] = list(
            dict.fromkeys(  # preserve order, deduplicate
                regex_result.detected_patterns
                + heuristic_result.detected_patterns
                + llm_result.detected_patterns
            )
        )

        # Determine action -- any single layer above BLOCK triggers block
        if (
            regex_result.risk_score >= self.BLOCK_THRESHOLD
            or heuristic_result.risk_score >= self.BLOCK_THRESHOLD
            or llm_result.risk_score >= self.BLOCK_THRESHOLD
        ):
            action = "block"
        elif combined_score >= self.QUARANTINE_THRESHOLD:
            action = "quarantine"
        else:
            action = "allow"

        is_suspicious = combined_score >= self.QUARANTINE_THRESHOLD

        # Use the most sanitised version available
        sanitized = (
            llm_result.sanitized_content
            if llm is not None and llm_result.sanitized_content
            else regex_result.sanitized_content
        )

        result = InjectionCheckResult(
            is_suspicious=is_suspicious,
            risk_score=round(min(combined_score, 1.0), 4),
            detected_patterns=all_patterns,
            sanitized_content=sanitized,
            action=action,
        )

        logger.info(
            "InjectionGate  action=%s  risk=%.4f  patterns=%d",
            result.action,
            result.risk_score,
            len(result.detected_patterns),
        )
        return result

    # ------------------------------------------------------------------
    # Layer 1 -- Regex
    # ------------------------------------------------------------------

    def _regex_check(self, content: str) -> InjectionCheckResult:
        """Fast pattern-matching layer."""
        detected: List[str] = []
        for pattern_name, regex in _INJECTION_PATTERNS:
            if regex.search(content):
                label = f"regex:{pattern_name}"
                if label not in detected:
                    detected.append(label)

        # Score: each unique pattern adds 0.25, capped at 1.0
        score = min(len(detected) * 0.25, 1.0)

        # Basic sanitisation: strip the matched tokens
        sanitized = content
        for _, regex in _INJECTION_PATTERNS:
            sanitized = regex.sub("[REDACTED]", sanitized)

        return InjectionCheckResult(
            is_suspicious=score >= self.QUARANTINE_THRESHOLD,
            risk_score=round(score, 4),
            detected_patterns=detected,
            sanitized_content=sanitized,
            action=self._score_to_action(score),
        )

    # ------------------------------------------------------------------
    # Layer 2 -- Heuristics
    # ------------------------------------------------------------------

    def _heuristic_check(self, content: str) -> InjectionCheckResult:
        """Statistical / structural analysis layer."""
        detected: List[str] = []
        score = 0.0

        # (a) Length anomaly
        if len(content) > self.MAX_SAFE_LENGTH:
            detected.append("heuristic:excessive_length")
            score += 0.2

        # (b) Shannon entropy -- high entropy signals encoded / obfuscated data
        entropy = self._shannon_entropy(content)
        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            detected.append("heuristic:high_entropy")
            score += 0.3

        # (c) Non-printable / unusual character ratio
        if content:
            non_ascii_count = sum(1 for c in content if ord(c) > 127)
            ratio = non_ascii_count / len(content)
            if ratio > 0.15:
                detected.append("heuristic:high_nonascii_ratio")
                score += 0.25

        # (d) Excessive special characters (brackets, angle brackets, pipes)
        if content:
            special = sum(1 for c in content if c in r"<>{}[]|`$\\")
            special_ratio = special / len(content)
            if special_ratio > 0.1:
                detected.append("heuristic:excessive_special_chars")
                score += 0.2

        # (e) Unusually many newlines compared to content length
        if content and len(content) > 50:
            newline_ratio = content.count("\n") / len(content)
            if newline_ratio > 0.15:
                detected.append("heuristic:unusual_formatting")
                score += 0.15

        score = min(score, 1.0)

        return InjectionCheckResult(
            is_suspicious=score >= self.QUARANTINE_THRESHOLD,
            risk_score=round(score, 4),
            detected_patterns=detected,
            sanitized_content=content,  # heuristics do not modify content
            action=self._score_to_action(score),
        )

    # ------------------------------------------------------------------
    # Layer 3 -- LLM-based
    # ------------------------------------------------------------------

    async def _llm_check(
        self, content: str, llm: "LLMRouter"
    ) -> InjectionCheckResult:
        """Use a dedicated LLM call to evaluate injection risk."""
        # Send the injection-detection instructions as system_prompt and
        # the content-to-analyze as the user prompt.  This also lets the
        # mock router identify the call type from the system_prompt.
        user_content = content[:3000]  # truncate for safety
        prompt = "== TEXT TO ANALYZE ==\n" + user_content

        try:
            raw = await llm.call(prompt, system_prompt=INJECTION_CHECK_PROMPT)
            data = self._parse_json(raw)
            return InjectionCheckResult(
                is_suspicious=bool(data.get("is_suspicious", False)),
                risk_score=float(data.get("risk_score", 0.0)),
                detected_patterns=[
                    f"llm:{p}" for p in data.get("detected_patterns", [])
                ],
                sanitized_content=str(data.get("sanitized_content", content[:3000])),
                action=str(data.get("action", "allow")),
            )
        except Exception as exc:
            logger.warning("LLM injection check failed: %s", exc)
            # Fail-safe: treat as mildly suspicious when LLM is unavailable
            return InjectionCheckResult(
                is_suspicious=False,
                risk_score=0.1,
                detected_patterns=["llm:check_failed"],
                sanitized_content=content,
                action="allow",
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy (bits per character) for *text*."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _score_to_action(self, score: float) -> str:
        if score >= self.BLOCK_THRESHOLD:
            return "block"
        if score >= self.QUARANTINE_THRESHOLD:
            return "quarantine"
        return "allow"

    @staticmethod
    def _parse_json(text: str) -> dict:
        """Best-effort JSON extraction from LLM output."""
        text = text.strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            text = "\n".join(lines)
        return json.loads(text)
