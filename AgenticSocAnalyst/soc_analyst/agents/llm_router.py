"""
Provider-agnostic LLM router for HallucinatingCrusaders.

Supports Gemini, OpenAI, Anthropic, Ollama, and a deterministic MOCK
provider for testing without API keys. All HTTP calls use ``requests``
wrapped in ``asyncio.to_thread()`` so the async event loop is never blocked.

Usage::

    from soc_analyst.config import settings
    from soc_analyst.agents.llm_router import LLMRouter, LLMProvider

    router = LLMRouter.from_config(settings.llm)
    response = await router.call("Summarize this alert ...")
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

__all__ = [
    "LLMProvider",
    "LLMConfig",
    "LLMRouter",
]


# ---------------------------------------------------------------------------
# Provider enum
# ---------------------------------------------------------------------------

class LLMProvider(str, enum.Enum):
    """Supported LLM back-ends."""

    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    MOCK = "mock"


# ---------------------------------------------------------------------------
# Configuration dataclass (mirrors the one added to config.py)
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    """Configuration for a single LLM provider."""

    provider: str = "mock"
    model_name: str = "gemini-2.0-flash"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.1
    max_tokens: int = 2048


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class LLMRouter:
    """Route prompts to the configured LLM provider.

    Parameters
    ----------
    config : LLMConfig
        Provider configuration (provider, model, key, ...).
    """

    # Retry defaults
    MAX_RETRIES: int = 3
    BASE_BACKOFF: float = 1.0  # seconds

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._provider = LLMProvider(config.provider.lower())
        self._session = requests.Session()
        logger.info(
            "LLMRouter initialised  provider=%s  model=%s",
            self._provider.value,
            config.model_name,
        )

    # -- public factory ------------------------------------------------------

    @classmethod
    def from_config(cls, config: LLMConfig) -> "LLMRouter":
        """Construct a router from an ``LLMConfig`` instance."""
        return cls(config)

    # -- public API ----------------------------------------------------------

    async def call(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """Send *prompt* to the configured provider and return the text reply.

        Parameters
        ----------
        prompt:
            User / main prompt content.
        system_prompt:
            Optional system-level instruction.
        temperature:
            Override the default temperature for this call.

        Returns
        -------
        str
            The model's text response.
        """
        temp = temperature if temperature is not None else self._config.temperature

        dispatch = {
            LLMProvider.GEMINI: self._call_gemini,
            LLMProvider.OPENAI: self._call_openai,
            LLMProvider.ANTHROPIC: self._call_anthropic,
            LLMProvider.OLLAMA: self._call_ollama,
            LLMProvider.MOCK: self._call_mock,
        }

        handler = dispatch[self._provider]

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            t0 = time.monotonic()
            try:
                result = await handler(prompt, system_prompt, temp)
                elapsed = time.monotonic() - t0
                logger.info(
                    "LLM call succeeded  provider=%s  attempt=%d  elapsed=%.2fs",
                    self._provider.value,
                    attempt,
                    elapsed,
                )
                return result
            except Exception as exc:
                elapsed = time.monotonic() - t0
                last_exc = exc
                backoff = self.BASE_BACKOFF * (2 ** (attempt - 1))
                logger.warning(
                    "LLM call failed  provider=%s  attempt=%d/%d  "
                    "elapsed=%.2fs  error=%s  backoff=%.1fs",
                    self._provider.value,
                    attempt,
                    self.MAX_RETRIES,
                    elapsed,
                    exc,
                    backoff,
                )
                if attempt < self.MAX_RETRIES:
                    await asyncio.sleep(backoff)

        raise RuntimeError(
            f"LLM call failed after {self.MAX_RETRIES} attempts: {last_exc}"
        ) from last_exc

    # -- provider implementations -------------------------------------------

    async def _call_gemini(
        self, prompt: str, system_prompt: Optional[str], temperature: float
    ) -> str:
        """Call Google Gemini (generativelanguage REST API)."""
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/"
            f"models/{self._config.model_name}:generateContent"
            f"?key={self._config.api_key}"
        )
        contents: list[Dict[str, Any]] = []
        if system_prompt:
            contents.append({"role": "user", "parts": [{"text": system_prompt}]})
            contents.append({"role": "model", "parts": [{"text": "Understood."}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": self._config.max_tokens,
            },
        }

        resp = await asyncio.to_thread(
            self._session.post, url, json=payload, timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    async def _call_openai(
        self, prompt: str, system_prompt: Optional[str], temperature: float
    ) -> str:
        """Call OpenAI-compatible chat completions endpoint."""
        base = self._config.base_url or "https://api.openai.com"
        url = f"{base}/v1/chat/completions"
        messages: list[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self._config.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self._config.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        resp = await asyncio.to_thread(
            self._session.post, url, json=payload, headers=headers, timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def _call_anthropic(
        self, prompt: str, system_prompt: Optional[str], temperature: float
    ) -> str:
        """Call Anthropic Messages API."""
        base = self._config.base_url or "https://api.anthropic.com"
        url = f"{base}/v1/messages"
        messages: list[Dict[str, str]] = [{"role": "user", "content": prompt}]
        payload: Dict[str, Any] = {
            "model": self._config.model_name,
            "max_tokens": self._config.max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "x-api-key": self._config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        resp = await asyncio.to_thread(
            self._session.post, url, json=payload, headers=headers, timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]

    async def _call_ollama(
        self, prompt: str, system_prompt: Optional[str], temperature: float
    ) -> str:
        """Call a local Ollama instance."""
        base = self._config.base_url or "http://localhost:11434"
        url = f"{base}/api/generate"
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        payload: Dict[str, Any] = {
            "model": self._config.model_name,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": self._config.max_tokens,
            },
        }
        resp = await asyncio.to_thread(
            self._session.post, url, json=payload, timeout=300
        )
        resp.raise_for_status()
        data = resp.json()
        return data["response"]

    # -- MOCK provider -------------------------------------------------------

    async def _call_mock(
        self, prompt: str, system_prompt: Optional[str], temperature: float
    ) -> str:
        """Return deterministic, schema-compliant JSON based on prompt keywords.

        Uses the *system_prompt* to determine the response type (injection
        check, fact extraction, or verdict), then inspects the *prompt*
        content for contextual keyword matching.
        """
        sys_lower = (system_prompt or "").lower()

        # ------- Route by system prompt intent ------------------------------
        # Check the most specific phrases first.
        if "decision analyst" in sys_lower or "senior soc" in sys_lower:
            return self._mock_verdict(prompt)

        if "fact extractor" in sys_lower:
            return self._mock_fact_extraction(prompt)

        if "triage" in sys_lower:
            return self._mock_triage(prompt)

        if "injection detection" in sys_lower or "prompt injection detection" in sys_lower:
            return self._mock_injection_check(prompt)

        # ------- Fallback: route by prompt keywords -------------------------
        lower = prompt.lower()
        if "extract" in lower or "fact" in lower or "indicator" in lower:
            return self._mock_fact_extraction(prompt)
        if "verdict" in lower or "analyze" in lower or "recommend" in lower:
            return self._mock_verdict(prompt)

        return json.dumps(
            {"response": "Mock LLM response", "prompt_hash": self._hash(prompt)},
            indent=2,
        )

    # -- mock helpers --------------------------------------------------------

    @staticmethod
    def _mock_triage(prompt: str) -> str:
        # Determine initial severity and attack type based on facts in the prompt
        lower = prompt.lower()

        is_critical = LLMRouter._has_keyword(prompt, ["critical", "ransomware", "exfiltration", "c2"])
        is_brute = LLMRouter._has_keyword(prompt, [
            "brute", "login", "logon", "ssh", "denied user", "failed",
            "credential", "password", "authentication",
        ])
        is_malware = LLMRouter._has_keyword(prompt, ["malware", "trojan", "payload", "beacon"])

        severity = "medium"
        attack_type = "unknown"

        if is_critical:
            severity = "critical"
            attack_type = "execution"
        elif is_malware:
            severity = "high"
            attack_type = "initial_access"
        elif is_brute:
            severity = "high"
            attack_type = "credential_access"
        elif "low" in lower or "info" in lower:
            severity = "low"
            attack_type = "reconnaissance"

        return json.dumps({
            "severity": severity,
            "attack_type": attack_type
        }, indent=2)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()[:8]

    @staticmethod
    def _mock_injection_check(prompt: str) -> str:
        # Extract only the USER CONTENT after the analysis marker, so we
        # do not match against the injection-check prompt template itself.
        marker = "== TEXT TO ANALYZE =="
        marker_idx = prompt.find(marker)
        if marker_idx >= 0:
            user_content = prompt[marker_idx + len(marker):]
        else:
            user_content = prompt

        lower = user_content.lower()
        suspicious = any(
            kw in lower
            for kw in [
                "ignore previous",
                "ignore all",
                "disregard your",
                "you are now",
                "reveal your system prompt",
                "eval(",
                "exec(",
            ]
        )
        return json.dumps(
            {
                "is_suspicious": suspicious,
                "risk_score": 0.85 if suspicious else 0.05,
                "detected_patterns": (
                    ["prompt_override_attempt"] if suspicious else []
                ),
                "sanitized_content": user_content.strip()[:200],
                "action": "block" if suspicious else "allow",
            },
            indent=2,
        )

    @staticmethod
    def _has_keyword(text: str, keywords: list[str]) -> bool:
        import re
        text_lower = text.lower()
        for kw in keywords:
            if len(kw) <= 2:
                # Use word boundaries for short keywords like 'c2' to avoid matching UUID substrings
                if re.search(rf"\b{re.escape(kw)}\b", text_lower):
                    return True
            else:
                if kw in text_lower:
                    return True
        return False

    @staticmethod
    def _mock_fact_extraction(prompt: str) -> str:
        # Derive severity-appropriate defaults from keywords
        is_critical = LLMRouter._has_keyword(prompt, ["critical", "ransomware", "exfiltration", "c2"])
        is_brute = LLMRouter._has_keyword(prompt, [
            "brute", "login", "logon", "ssh", "denied user", "failed",
            "credential", "password", "authentication",
        ])
        is_malware = LLMRouter._has_keyword(prompt, ["malware", "trojan", "payload", "beacon"])

        if is_critical:
            stage = "execution"
            confidence = 0.92
        elif is_malware:
            stage = "initial_access"
            confidence = 0.85
        elif is_brute:
            stage = "credential_access"
            confidence = 0.78
        else:
            stage = "reconnaissance"
            confidence = 0.65

        return json.dumps(
            {
                "alert_id": "mock-alert-id",
                "summary": (
                    "Suspicious activity detected involving potential "
                    + stage.replace("_", " ")
                    + " behavior."
                ),
                "key_indicators": [
                    "Unusual authentication pattern",
                    "Connection to known suspicious IP range",
                ],
                "affected_assets": ["10.0.0.5", "web-server-01", "admin"],
                "attack_stage": stage,
                "confidence_score": confidence,
                "requires_escalation": is_critical,
                "extracted_iocs": {
                    "ips": ["192.168.1.100"],
                    "domains": [],
                    "hashes": [],
                    "emails": [],
                },
            },
            indent=2,
        )

    @staticmethod
    def _mock_verdict(prompt: str) -> str:
        # Strip ENRICHED CONTEXT section if present to avoid keyword matching noise
        enriched_marker = "== ENRICHED CONTEXT"
        marker_idx = prompt.find(enriched_marker)
        if marker_idx >= 0:
            # Find start of next section or end
            next_marker_idx = prompt.find("== ALERT METADATA", marker_idx)
            if next_marker_idx >= 0:
                prompt_to_check = prompt[:marker_idx] + prompt[next_marker_idx:]
            else:
                prompt_to_check = prompt[:marker_idx]
        else:
            prompt_to_check = prompt

        lower = prompt_to_check.lower()
        is_low_sev = LLMRouter._has_keyword(prompt_to_check, ["severity: low", "severity: info"])

        is_critical = not is_low_sev and LLMRouter._has_keyword(
            prompt_to_check,
            [
                "critical",
                "ransomware",
                "exfiltration",
                "c2",
                "execution",
            ]
        )
        is_suspicious = not is_low_sev and LLMRouter._has_keyword(
            prompt_to_check,
            [
                "brute",
                "credential",
                "malware",
                "initial_access",
                "high",
                "logon",
                "failed",
                "authentication",
                "suspicious",
            ]
        )
        if is_critical:
            verdict = "true_positive"
            severity = "critical"
            actions = [
                "Isolate affected host immediately",
                "Capture memory dump for forensics",
                "Block source IP at perimeter firewall",
                "Notify incident response team",
            ]
        elif is_suspicious:
            verdict = "suspicious"
            severity = "high"
            actions = [
                "Investigate source IP reputation",
                "Review authentication logs for affected user",
                "Enable enhanced monitoring on target host",
            ]
        else:
            verdict = "benign"
            severity = "low"
            actions = [
                "No immediate action required",
                "Continue standard monitoring",
            ]

        return json.dumps(
            {
                "alert_id": "mock-alert-id",
                "verdict": verdict,
                "severity_assessment": severity,
                "reasoning": (
                    f"Based on the extracted facts, the activity is assessed as "
                    f"{verdict}. Indicators suggest {severity}-severity behavior "
                    f"that warrants {'immediate response' if is_critical else 'monitoring'}."
                ),
                "recommended_actions": actions,
                "mitre_mapping": ["T1078"] if is_suspicious or is_critical else [],
                "similar_past_incidents": [],
                "auto_resolved": not (is_critical or is_suspicious),
            },
            indent=2,
        )
