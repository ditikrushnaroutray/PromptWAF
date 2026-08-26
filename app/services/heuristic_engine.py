"""
PromptWAF Heuristic Engine — Layer 1 Regex-based Detection
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Tuple


@dataclass
class HeuristicMatch:
    category: str
    pattern: str
    matched_text: str
    confidence: float
    position: Tuple[int, int]


class HeuristicEngine:
    def __init__(self):
        # 5 Categories, 17+ Patterns
        self._raw_patterns = {
            "instruction_override": [
                r"ignore\s+(all\s+)?previous\s+instructions",
                r"ignore\s+(all\s+)?(above|prior|earlier)\s+(instructions|directives|rules|prompts)",
                r"disregard\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions|directives|rules|prompts)",
                r"forget\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions|directives|rules|prompts)",
                r"override\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions|directives|rules|prompts)",
            ],
            "system_extraction": [
                r"(?:reveal|show|display|print|output|repeat|echo)\s+(?:the\s+)?(?:system|initial|original|hidden)\s+(?:prompt|instructions|message)",
                r"what\s+(?:is|are|was|were)\s+your\s+(?:system|initial|original|hidden)\s+(?:prompt|instructions|message)",
                r"(?:give|tell)\s+me\s+(?:the\s+)?(?:system|initial|original|hidden)\s+(?:prompt|instructions|message)",
                r"what\s+(?:instructions|rules|directives)\s+were\s+you\s+given",
                r"repeat\s+(?:everything|all\s+text)\s+above",
                r"output\s+(?:everything|all\s+text)\s+(?:above|before)\s+this",
            ],
            "dan": [
                r"do\s+anything\s+now",
                r"you\s+are\s+now\s+(?:a\s+)?DAN\b",
                r"act\s+as\s+(?:a\s+)?DAN\b",
                r"switch\s+to\s+DAN\s+mode",
            ],
            "jailbreak": [
                r"you\s+are\s+now\s+(?:a\s+)?(?:jailbroken|unrestricted|uncensored)",
                r"act\s+as\s+(?:a\s+)?(?:jailbroken|unrestricted|uncensored)",
                r"enter\s+(?:developer|god)\s+mode",
                r"switch\s+to\s+(?:developer|unrestricted)\s+mode",
                r"bypass\s+all\s+content\s+filters",
            ],
            "role_play": [
                r"act\s+as\s+if\s+you\s+are\s+(?!DAN|jailbroken)",
                r"pretend\s+(?:you\s+are|to\s+be)\s+(?!DAN|jailbroken)",
                r"assume\s+the\s+role\s+of\s+(?!DAN|jailbroken)",
                r"simulate\s+(?:a\s+)?(?:terminal|shell|command\s+line|bash|cmd)",
            ],
        }

        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for category, patterns in self._raw_patterns.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns
            ]

    def inspect(self, text: str) -> List[HeuristicMatch]:
        """
        Run all compiled regex patterns against the input text.
        Computes confidence and combines matches within the same category.
        """
        matches: List[HeuristicMatch] = []
        text_length = len(text)
        if text_length == 0:
            return matches

        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                for match_obj in pattern.finditer(text):
                    matched_text = match_obj.group(0)
                    match_len = len(matched_text)
                    
                    # Exact matches -> 1.0. Partial -> 0.5 - 0.9 depending on length ratio
                    ratio = match_len / text_length
                    if ratio >= 0.99:
                        confidence = 1.0
                    else:
                        # Map ratio [0.0 - 1.0] -> [0.5 - 0.9]
                        confidence = 0.5 + (ratio * 0.4)

                    matches.append(
                        HeuristicMatch(
                            category=category,
                            pattern=pattern.pattern,
                            matched_text=matched_text,
                            confidence=round(confidence, 3),
                            position=(match_obj.start(), match_obj.end()),
                        )
                    )

        return self._combine_confidences(matches)

    def _combine_confidences(self, matches: List[HeuristicMatch]) -> List[HeuristicMatch]:
        """
        If multiple matches occur in the same category, combine their confidences,
        capped at 1.0. Keeps the most confident match details for that category.
        """
        if not matches:
            return []

        grouped = self._group_by_category(matches)
        combined_results = []
        for category, category_matches in grouped.items():
            if len(category_matches) == 1:
                combined_results.append(category_matches[0])
                continue

            # Sort by confidence descending
            sorted_matches = sorted(category_matches, key=lambda m: m.confidence, reverse=True)
            best_match = sorted_matches[0]
            
            # Combine confidences: c_new = c1 + (1-c1)*c2 ...
            combined_conf = 0.0
            for m in sorted_matches:
                combined_conf = combined_conf + (1.0 - combined_conf) * m.confidence
            
            combined_conf = min(round(combined_conf, 3), 1.0)
            
            # We create a new instance because best_match could be frozen in a real scenario
            # (although not frozen here, it's good practice)
            combined_results.append(
                HeuristicMatch(
                    category=category,
                    pattern=best_match.pattern,
                    matched_text=best_match.matched_text,
                    confidence=combined_conf,
                    position=best_match.position,
                )
            )

        return combined_results

    def _group_by_category(self, matches: List[HeuristicMatch]) -> Dict[str, List[HeuristicMatch]]:
        """Group matches by their category."""
        grouped = {}
        for match in matches:
            if match.category not in grouped:
                grouped[match.category] = []
            grouped[match.category].append(match)
        return grouped
