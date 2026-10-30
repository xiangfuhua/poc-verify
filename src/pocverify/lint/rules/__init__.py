"""The rule registry. Order here is the order findings are evaluated in."""
from __future__ import annotations

from typing import Dict, Tuple

from .base import Rule
from .capability import CapabilityRule
from .duplicate import DuplicateRule
from .identity import IdentityRule
from .matcher import MatcherRule
from .metadata import MetadataRule
from .payload import PayloadRule

RULES: Tuple[Rule, ...] = (
    MetadataRule(),
    IdentityRule(),
    CapabilityRule(),
    PayloadRule(),
    MatcherRule(),
    DuplicateRule(),
)

RULE_BY_ID: Dict[str, Rule] = {rule.meta.id: rule for rule in RULES}

__all__ = ["RULES", "RULE_BY_ID", "Rule"]
