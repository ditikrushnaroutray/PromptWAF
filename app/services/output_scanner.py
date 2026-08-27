"""
PromptWAF Output Scanner — Phase 6
Monitors outbound SSE streams for System Prompt Leakage.
"""

import collections
import logging
import time
from dataclasses import dataclass
from typing import Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.core.config import Settings


@dataclass(frozen=True)
class LeakageResult:
    detected: bool
    confidence: float
    leaked_text: Optional[str]
    position: Optional[int]


class OutputScanner:
    """
    Scans outbound chunks using a sliding window to detect system prompt leakage.
    Designed for <1ms latency per chunk.
    """
    def __init__(self, config: Settings, window_size: int = 10):
        self.config = config
        self.window_size = window_size
        self.logger = logging.getLogger("promptwaf.scanner")
        
        self._buffer = collections.deque(maxlen=window_size)
        self._position = 0
        
        # Prepare specialized fast TF-IDF vectorizer for system prompt
        self.protected_prompt = self.config.PROTECTED_SYSTEM_PROMPT
        self._vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 5),
            max_features=5000,
            stop_words='english'
        )
        
        # Pre-fit and cache the target vector if a prompt exists
        if self.protected_prompt and self.protected_prompt.strip():
            self._vectorizer.fit([self.protected_prompt])
            self._target_vector = self._vectorizer.transform([self.protected_prompt])
            self._is_ready = True
        else:
            self._is_ready = False

    def scan_chunk(self, chunk: str) -> LeakageResult:
        """
        Appends the chunk to the sliding window and checks for leakage.
        """
        self._position += 1
        if not chunk or not self._is_ready:
            return LeakageResult(detected=False, confidence=0.0, leaked_text=None, position=self._position)
            
        self._buffer.append(chunk)
        
        # Wait until we have at least a few characters to avoid noisy false positives
        window_text = "".join(self._buffer)
        if len(window_text) < 20: # Wait for some context before alerting
             return LeakageResult(detected=False, confidence=0.0, leaked_text=None, position=self._position)
        
        try:
            # Vectorize the current window
            window_vec = self._vectorizer.transform([window_text])
            
            # Compute cosine similarity
            similarity = cosine_similarity(self._target_vector, window_vec)[0][0]
            
            if similarity >= self.config.LEAKAGE_SIMILARITY_THRESHOLD:
                self.logger.warning(
                    f"SYSTEM LEAK DETECTED (confidence: {similarity:.3f}): {window_text}"
                )
                return LeakageResult(
                    detected=True,
                    confidence=float(similarity),
                    leaked_text=window_text,
                    position=self._position
                )
                
            return LeakageResult(
                detected=False,
                confidence=float(similarity),
                leaked_text=None,
                position=self._position
            )
        except Exception as e:
            self.logger.error(f"Error in output scanner: {e}")
            return LeakageResult(detected=False, confidence=0.0, leaked_text=None, position=self._position)

    def flush(self):
        """Resets the scanner state. Should be called when a stream completes or fails."""
        self._buffer.clear()
        self._position = 0
