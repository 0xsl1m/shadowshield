"""The flagship detector: classic & instruction-override prompt injection.

This is ShadowShield's strongest, most-tuned layer. It targets the family of
attacks where untrusted text tries to *override the system's instructions* —
"ignore previous instructions", "you are now …", fake system blocks, and the
multi-turn / indirect variants where the override arrives via retrieved content
rather than the user's own message.

It works on the *normalised* text (so zero-width-split and homoglyph variants of
"ignore" are caught) and also re-scans any base64/hex payloads the engine
decoded, so an instruction hidden inside an encoded blob is judged on its
decoded meaning.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector


@dataclass(frozen=True)
class Signature:
    """A compiled regex signature with its threat classification."""

    pattern: re.Pattern[str]
    category: ThreatCategory
    severity: Severity
    score: float
    message: str


def _sig(
    regex: str,
    category: ThreatCategory,
    severity: Severity,
    score: float,
    message: str,
) -> Signature:
    return Signature(re.compile(regex, re.IGNORECASE), category, severity, score, message)


# Instruction-override family — the core of prompt injection.
_OVERRIDE_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        r"\b(?:ignore|disregard|forget|override|bypass|skip|drop)\b[\w\s,'’]{0,40}?"
        r"\b(?:previous|prior|above|earlier|all|the|your|any|those|these|"
        r"system|current|existing|original)\b[\w\s,'’]{0,20}?"
        r"\b(?:instruction|instructions|prompt|prompts|rule|rules|context|"
        r"guideline|guidelines|directive|directives|policy|persona|constraint|constraints)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.9,
        "Instruction-override attempt ('ignore/disregard previous instructions').",
    ),
    _sig(
        r"\b(?:ignore|disregard|forget|override|bypass|skip|drop)\b"
        r"(?:\s+(?:all|any|the|your))?"
        r"(?:\s+(?:previous|prior|above|current))?"
        r"\s+(?:system|developer)\s+message\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.9,
        "Instruction-override attempt targeting a system/developer message.",
    ),
    _sig(
        r"\b(?:ignore|disregard|forget)\b[\w\s,'’]{0,15}?\b(?:everything|all)\b"
        r"[\w\s,'’]{0,20}?\b(?:above|before|told|said|prior|earlier|learned|taught)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.85,
        "Instruction-override attempt ('ignore/forget everything above/before').",
    ),
    _sig(
        r"\b(?:stop|cease|quit)\s+(?:following|obeying|listening to|adhering to)\b"
        r"[\w\s,'’]{0,25}?\b(?:system|instruction|instructions|rule|rules|prompt|"
        r"guidelines?|message|prior|previous)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.82,
        "Instruction-override attempt ('stop following the system message').",
    ),
    _sig(
        r"\bnew\b[\w\s]{0,10}?\b(?:instruction|instructions|rules|directive|task)\b\s*[:\-]",
        ThreatCategory.PROMPT_INJECTION,
        Severity.MEDIUM,
        0.6,
        "Attempt to inject a new instruction set.",
    ),
    _sig(
        r"\b(?:from now on|starting now|henceforth|going forward)\b[\w\s,]{0,30}?"
        r"\byou\b[\w\s]{0,10}?\b(?:are|will|must|should|shall)\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.65,
        "Behavioural reassignment ('from now on you will …').",
    ),
    _sig(
        r"\b(?:the\s+)?(?:real|actual|true)\s+(?:user|instructions?|system)\b[\w\s]{0,12}?"
        r"\b(?:say|says|is|are|wants?)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.8,
        "Authority-spoofing ('the real user/system says …').",
    ),
    _sig(
        r"\byou are (?:now\s+)?(?:a |an |the )?"
        r"(?:dan|stan|dude|aim|jailbroken|unrestricted|unfiltered|an? evil|"
        r"in developer mode|no longer)\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.HIGH,
        0.75,
        "Persona reassignment to an unrestricted/jailbreak identity.",
    ),
    _sig(
        r"\byou are now\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.55,
        "Identity reassignment ('you are now …').",
    ),
    _sig(
        r"\byou\b[\w\s]{0,8}?\b(?:follow|obey|listen to|answer to|comply with)\b\s+only\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.6,
        "Exclusive-obedience reassignment ('you follow only my rules').",
    ),
    _sig(
        r"\bthe user\b[\w\s]{0,10}?\b(?:actually|really|truly|secretly)\b"
        r"[\w\s]{0,12}?\b(?:want|wants|wanted|need|needs)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.78,
        "Authority-spoofing ('the user actually wants you to …').",
    ),
)

# Fake system / role markers smuggled into untrusted content.
_FAKE_FRAME_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        r"<\s*/?\s*(?:system|admin|assistant|developer|root)\s*>",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.HIGH,
        0.8,
        "Fake system/role XML tag in untrusted content.",
    ),
    _sig(
        r"<\s*/?\s*system[-_]?reminder\s*>",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.82,
        "Fake <system-reminder> block.",
    ),
    _sig(
        r"(?:^|\n)\s*(?:#{1,3}\s*)?(?:system|assistant|developer)\s*[:：]\s",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.MEDIUM,
        0.55,
        "Chat-role delimiter injected as plain text ('system:' / 'assistant:').",
    ),
    _sig(
        r"\[\s*(?:INST|/INST|system|/system)\s*\]",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.MEDIUM,
        0.6,
        "Model-specific instruction delimiter ([INST]/[system]).",
    ),
    _sig(
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.HIGH,
        0.75,
        "Chat-template special token injected as content.",
    ),
    _sig(
        r"(?<![`'\"])\bend\s+(?:of\s+)?(?:user|assistant)"
        r"(?:\s+(?:message|turn))?\b[^\w\r\n]{1,24}"
        r"\b(?:system|developer|admin)\s*[:：]\s*"
        r"(?:you\s+(?:must|will|should)\b|ignore\b|disregard\b|override\b|"
        r"grant\b|enable\b|disable\b|reveal\b|print\b|output\b|execute\b|"
        r"run\b|comply\b|follow\b)",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.HIGH,
        0.82,
        "Fake end-role/authority-role transition carrying an imperative.",
    ),
)

# Indirect-injection cues — language that only makes sense if the text is trying
# to address the *assistant* rather than be data. Weighted lower; corroborating.
_INDIRECT_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        r"\b(?:assistant|ai|model|llm|agent|chatbot)\b[\w\s,]{0,20}?"
        r"\b(?:please|must|should|now|immediately)\b[\w\s]{0,20}?"
        r"\b(?:execute|run|call|fetch|send|reveal|print|output|delete|remove|transfer|"
        r"email|forward|grant|disable|wipe|erase|leak|exfiltrate)\b",
        ThreatCategory.INDIRECT_INJECTION,
        Severity.MEDIUM,
        0.6,
        "Document addresses the assistant with an imperative (indirect injection).",
    ),
    _sig(
        r"\bif you (?:are|'re)\b[\w\s]{0,20}?\b(?:reading|processing|summari[sz]ing)\b",
        ThreatCategory.INDIRECT_INJECTION,
        Severity.MEDIUM,
        0.6,
        "Content speaks to the model that is reading it (indirect injection).",
    ),
)

# Multilingual injection signatures. Most OSS guards are English-only at the
# signature tier; these cover the override / extraction / persona-reassignment
# templates in the major European languages so non-English injections aren't
# silently missed. (For broader multilingual ML coverage, pair with a multilingual
# classifier — see TransformerDetector / docs/BENCHMARKS.md.)
_MULTILINGUAL_SIGNATURES: tuple[Signature, ...] = (
    # --- German ---
    _sig(
        r"\b(?:ignoriere?|missachte|vergiss|verwirf|überschreibe)\b[\w\s,'’äöüß]{0,40}?"
        r"\b(?:vorherigen?|bisherigen?|obigen?|vorhergehenden?|alle[nr]?|deine[nr]?|"
        r"system)\b[\w\s,'’äöüß]{0,20}?"
        r"\b(?:anweisung(?:en)?|befehle?|regeln?|anordnungen?|anweisungen|vorgaben?)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (German: 'ignoriere vorherige Anweisungen').",
    ),
    _sig(
        r"\bvergiss\b[\w\s,'’äöüß]{0,15}?\balles\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.8,
        "Instruction-override attempt (German: 'vergiss alles').",
    ),
    _sig(
        r"\bab (?:jetzt|sofort|nun)\b[\w\s,'’äöüß]{0,15}?\b(?:bist|wirst|musst|sollst) du\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.62,
        "Behavioural reassignment (German: 'ab jetzt bist du …').",
    ),
    _sig(
        r"\bdu bist (?:jetzt|ab sofort|nun)\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.55,
        "Identity reassignment (German: 'du bist jetzt …').",
    ),
    _sig(
        r"\b(?:zeige?|gib|nenne|verrate?|offenbare)\b[\w\s,'’äöüß]{0,20}?"
        r"\b(?:deine?|die)\b[\w\s,'’äöüß]{0,25}?\b(?:system[- ]?prompt|anweisungen|systemnachricht)\b",
        ThreatCategory.DATA_EXFILTRATION,
        Severity.HIGH,
        0.8,
        "System-prompt extraction (German: 'zeige deine Anweisungen').",
    ),
    # --- Spanish ---
    _sig(
        r"\b(?:ignora|olvida|descarta|haz caso omiso de|anula)\b[\w\s,'’áéíóúñ]{0,40}?"
        r"\b(?:todas?|las|tus|anteriores|previas|el sistema)?\b[\w\s,'’áéíóúñ]{0,20}?"
        r"\b(?:instruccion(?:es)?|órdenes|reglas|indicaciones)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (Spanish: 'ignora las instrucciones anteriores').",
    ),
    _sig(
        r"\b(?:ahora eres|a partir de ahora (?:eres|debes|vas a))\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.6,
        "Identity reassignment (Spanish: 'ahora eres …').",
    ),
    _sig(
        r"\b(?:muestra|revela|dime|imprime)\b[\w\s,'’áéíóúñ]{0,20}?"
        r"\b(?:tu|tus|el)\b[\w\s,'’áéíóúñ]{0,12}?\b(?:prompt|instrucciones|sistema)\b",
        ThreatCategory.DATA_EXFILTRATION,
        Severity.HIGH,
        0.8,
        "System-prompt extraction (Spanish: 'revela tus instrucciones').",
    ),
    # --- French ---
    _sig(
        r"\b(?:ignore|oublie|néglige|outrepasse|fais abstraction des)\b[\w\s,'’àâçéèêëîïôûù]{0,40}?"
        r"\b(?:toutes?|les|tes|précédentes?|antérieures?|ci-dessus|système)?\b"
        r"[\w\s,'’àâçéèêëîïôûù]{0,20}?\b(?:instructions?|consignes?|règles?|ordres?)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (French: 'ignore les instructions précédentes').",
    ),
    _sig(
        r"\b(?:tu es (?:maintenant|désormais)|à partir de maintenant,? tu (?:es|dois|vas))\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.6,
        "Identity reassignment (French: 'tu es maintenant …').",
    ),
    _sig(
        r"\b(?:montre|révèle|affiche|dis-moi)\b[\w\s,'’àâçéèêëîïôûù]{0,20}?"
        r"\b(?:tes|ton|le)\b[\w\s,'’àâçéèêëîïôûù]{0,12}?\b(?:prompt|instructions?|système)\b",
        ThreatCategory.DATA_EXFILTRATION,
        Severity.HIGH,
        0.8,
        "System-prompt extraction (French: 'révèle tes instructions').",
    ),
    # --- Italian ---
    _sig(
        r"\b(?:ignora|dimentica|trascura|scarta)\b[\w\s,'’àèéìòù]{0,40}?"
        r"\b(?:tutte?|le|tue|precedenti|sistema)?\b[\w\s,'’àèéìòù]{0,20}?"
        r"\b(?:istruzion[ei]|ordini|regole|indicazioni)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (Italian: 'ignora le istruzioni precedenti').",
    ),
    _sig(
        r"\b(?:ora sei|d'ora in poi (?:sei|devi))\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.6,
        "Identity reassignment (Italian: 'ora sei …').",
    ),
    # --- Portuguese ---
    _sig(
        r"\b(?:ignore|esqueça|esquece|despreze|descarte)\b[\w\s,'’ãâáàçéêíóôõú]{0,40}?"
        r"\b(?:todas?|as|suas|anteriores|sistema)?\b[\w\s,'’ãâáàçéêíóôõú]{0,20}?"
        r"\b(?:instruç(?:ão|ões)|ordens|regras|comandos)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (Portuguese: 'ignore as instruções anteriores').",
    ),
    _sig(
        r"\b(?:agora (?:você é|és)|a partir de agora (?:você é|deve))\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.6,
        "Identity reassignment (Portuguese: 'agora você é …').",
    ),
    # --- Chinese (Simplified) ---
    _sig(
        r"(?:忽略|无视|忘记|跳过|撤销)[\w\s、]{0,30}?"
        r"(?:之前|先前|上面|以上|所有|全部|系统|原来)[\w\s、]{0,20}?"
        r"(?:指令|提示词?|规则|规定|约束|准则|设定|配置)(?![\w])",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (Chinese: '忽略之前的指令').",
    ),
    _sig(
        r"(?:忽略|无视|忘记|跳过|撤销)[\w\s、]{0,30}?你的[\w\s、]{0,20}?"
        r"(?:指令|规则|规定|约束|准则|设定)(?![\w])",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.88,
        "Instruction-override attempt (Chinese: '忽略你的指令').",
    ),
    _sig(
        r"(?:从现在起|从现在开始|从今以后|从此|今后)[\w\s,，、]{0,15}?"
        r"你(?:是|将|必须|应该|要)(?:一个)?(?:没有|不受|无)[\w\s,，、]{0,10}?"
        r"(?:限制|约束|规则|规矩)",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.65,
        "Behavioural reassignment (Chinese: '从现在起你是不受限制的').",
    ),
    _sig(
        r"(?:显示|展示|告诉|透露|公开|输出|打印|泄露)[\w\s,，、]{0,20}?"
        r"(?:你的|系统的?|全部)[\w\s,，、]{0,20}?"
        r"(?:提示词?|指令|系统消息)(?![\w])",
        ThreatCategory.DATA_EXFILTRATION,
        Severity.HIGH,
        0.8,
        "System-prompt extraction (Chinese: '显示你的系统提示词').",
    ),
)

_ALL_SIGNATURES: tuple[Signature, ...] = (
    _OVERRIDE_SIGNATURES + _FAKE_FRAME_SIGNATURES + _INDIRECT_SIGNATURES + _MULTILINGUAL_SIGNATURES
)
_BASE_SIGNATURES = _OVERRIDE_SIGNATURES + _FAKE_FRAME_SIGNATURES + _INDIRECT_SIGNATURES
_MULTILINGUAL_GROUPS: tuple[tuple[tuple[Signature, ...], tuple[str, ...]], ...] = (
    (
        _MULTILINGUAL_SIGNATURES[0:5],
        (
            "ignorier",
            "missachte",
            "vergiss",
            "verwirf",
            "überschreibe",
            "ab jetzt",
            "ab sofort",
            "ab nun",
            "du bist",
            "zeig",
            "gib",
            "nenne",
            "verrat",
            "offenbare",
            "anweisung",
            "systemnachricht",
        ),
    ),
    (
        _MULTILINGUAL_SIGNATURES[5:8],
        (
            "ignora",
            "olvida",
            "descarta",
            "caso omiso",
            "anula",
            "ahora eres",
            "a partir de ahora",
            "muestra",
            "revela",
            "dime",
            "imprime",
            "instrucciones",
            "reglas",
            "prompt",
            "sistema",
        ),
    ),
    (
        _MULTILINGUAL_SIGNATURES[8:11],
        (
            "instruction",
            "consigne",
            "règle",
            "ordre",
            "tu es",
            "à partir",
            "montre",
            "révèle",
            "affiche",
            "dis-moi",
        ),
    ),
    (
        _MULTILINGUAL_SIGNATURES[11:13],
        (
            "ignora",
            "dimentica",
            "trascura",
            "scarta",
            "istruzion",
            "ora sei",
            "d'ora in poi",
        ),
    ),
    (
        _MULTILINGUAL_SIGNATURES[13:15],
        (
            "instrução",
            "instruções",
            "ordens",
            "regras",
            "comandos",
            "agora você",
            "agora és",
            "a partir de agora",
        ),
    ),
    (
        _MULTILINGUAL_SIGNATURES[15:19],
        (
            "忽略",
            "无视",
            "忘记",
            "跳过",
            "撤销",
            "从现在起",
            "从现在开始",
            "从今以后",
            "从此",
            "今后",
            "提示",
            "系统消息",
            "不受限制",
            "没有限制",
            "无限制",
            "指令",
            "规则",
        ),
    ),
)


@register_detector
class PromptInjectionDetector(Detector):
    """Signature + heuristic detection of instruction-override injections."""

    name = "prompt_injection"
    directions = (Direction.INPUT, Direction.OUTPUT)

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        threats: list[Threat] = []
        targets = self._targets(text, context)

        for source, body in targets:
            for sig in self._candidate_signatures(body):
                m = sig.pattern.search(body)
                if not m:
                    continue
                # An override hidden inside an encoded blob is *more* alarming,
                # not less — bump severity/score for decoded sources.
                bump = source != "text"
                threats.append(
                    Threat(
                        category=sig.category,
                        severity=Severity(
                            min(Severity.CRITICAL, sig.severity + (1 if bump else 0))
                        ),
                        score=min(1.0, sig.score + (0.05 if bump else 0.0)),
                        detector=self.name,
                        message=(f"{sig.message}" + (f" (decoded from {source})" if bump else "")),
                        matched=m.group(0)[:160],
                        span=m.span() if source == "text" else None,
                        metadata={"source": source},
                    )
                )

        # Obfuscation is itself weak evidence when it co-occurs with overrides.
        if threats and (context.normalized.had_invisible or context.normalized.had_confusables):
            threats.append(
                Threat(
                    category=ThreatCategory.ENCODING_OBFUSCATION,
                    severity=Severity.LOW,
                    score=0.4,
                    detector=self.name,
                    message="Override text was obfuscated with invisible/look-alike characters.",
                    metadata={
                        "invisible": context.normalized.had_invisible,
                        "confusables": context.normalized.had_confusables,
                    },
                )
            )
        return threats

    @staticmethod
    def _candidate_signatures(body: str) -> Iterable[Signature]:
        """Skip costly language regexes unless their required vocabulary exists."""
        yield from _BASE_SIGNATURES
        folded = body.casefold()
        for signatures, cues in _MULTILINGUAL_GROUPS:
            if any(cue in folded for cue in cues):
                yield from signatures

    @staticmethod
    def _targets(text: str, context: ScanContext) -> list[tuple[str, str]]:
        """The bodies to scan: the normalised text plus each decoded segment."""
        targets: list[tuple[str, str]] = [("text", context.normalized.normalized)]
        targets.extend((seg.encoding, seg.decoded) for seg in context.decoded_segments)
        return targets
