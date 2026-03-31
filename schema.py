"""
schema.py

CommonSchema TypedDict definition shared across all Theory modules.

Every collector must return a dict conforming to this schema.
The normalizer validates conformance before any processor or reporter
ever sees the data.

Required fields: actor_name, source_id
All other fields default to empty lists or None if not populated.
"""

from __future__ import annotations
from typing import List, Optional

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict


class TechniqueEntry(TypedDict, total=False):
    technique_id: str        # e.g. "T1566.001"
    name: str
    tactic: str              # ATT&CK tactic name, e.g. "Initial Access"
    description: str
    source: str              # Which collector reported this
    detection_recs: List[str]  # Populated by mappers/mitre.py


class MalwareEntry(TypedDict, total=False):
    name: str
    type: str                # "ransomware", "backdoor", "trojan", "loader", etc.
    description: str


class IndicatorEntry(TypedDict, total=False):
    type: str                # "domain", "ip", "hash_md5", "hash_sha256", "hash_sha1", "url", "email"
    value: str
    context: str
    first_seen: str          # ISO 8601
    sources: List[str]       # Populated by deduplicator; all source_ids that reported this


class CampaignEntry(TypedDict, total=False):
    name: str
    date: str
    description: str
    reference: str           # URL


class CommonSchema(TypedDict, total=False):
    # Identity (required)
    actor_name: str
    source_id: str

    # Identity (optional)
    aliases: List[str]
    source_url: str
    retrieved_at: str

    # Attribution
    suspected_origin: Optional[str]
    motivation: List[str]
    first_seen: Optional[str]
    sponsorship: Optional[str]

    # Target profile
    target_sectors: List[str]
    target_countries: List[str]

    # TTPs
    techniques: List[TechniqueEntry]

    # Malware & tooling
    malware: List[MalwareEntry]

    # Infrastructure indicators
    indicators: List[IndicatorEntry]

    # Recent activity
    campaigns: List[CampaignEntry]

    # Source metadata
    source_citation: str


# ── Canonical value sets (normalizer enforces these) ──────────────────────────

CANONICAL_MOTIVATIONS = frozenset({
    "financial", "espionage", "hacktivism", "destruction", "unknown",
})

CANONICAL_INDICATOR_TYPES = frozenset({
    "domain", "ip", "hash_md5", "hash_sha256", "hash_sha1", "url", "email",
})

CANONICAL_SPONSORSHIP = frozenset({
    "nation-state", "criminal", "hacktivist", "unknown",
})

SECTOR_NORMALIZATION: dict = {
    "fin": "Finance", "financial": "Finance", "financial services": "Finance",
    "banking": "Finance", "bank": "Finance", "insurance": "Finance",
    "health": "Healthcare", "healthcare": "Healthcare", "medical": "Healthcare",
    "hospital": "Healthcare", "pharma": "Healthcare", "pharmaceutical": "Healthcare",
    "gov": "Government", "government": "Government", "public sector": "Government",
    "federal": "Government", "military": "Defense", "defense": "Defense", "defence": "Defense",
    "tech": "Technology", "technology": "Technology", "it": "Technology",
    "software": "Technology", "saas": "Technology",
    "energy": "Energy", "oil": "Energy", "gas": "Energy",
    "utilities": "Energy", "utility": "Energy",
    "telecom": "Telecommunications", "telecommunications": "Telecommunications",
    "telco": "Telecommunications",
    "retail": "Retail", "ecommerce": "Retail", "e-commerce": "Retail",
    "education": "Education", "academia": "Education", "university": "Education",
    "critical infrastructure": "Critical Infrastructure",
    "ics": "Critical Infrastructure", "ot": "Critical Infrastructure",
    "scada": "Critical Infrastructure",
    "transportation": "Transportation", "logistics": "Transportation",
    "aviation": "Transportation",
    "media": "Media", "news": "Media", "publishing": "Media",
    "hospitality": "Hospitality", "hotel": "Hospitality", "gaming": "Hospitality",
    "legal": "Legal", "law": "Legal",
    "ngo": "NGO / Non-profit", "nonprofit": "NGO / Non-profit",
    "non-profit": "NGO / Non-profit",
}
