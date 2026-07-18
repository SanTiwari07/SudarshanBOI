"""
SUDARSHAN — Network Capture
============================
Captures network traffic via mitmproxy (if configured) or falls back to
parsing Frida network hooks (OkHttp, URLConnection).
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

class NetworkCapture:
    def __init__(self, event_bus: Optional[RuntimeEventBus] = None):
        self.flows: List[Dict[str, Any]] = []
        
        # If mitmproxy is running, it could dump flows to a local socket or file,
        # but for this prototype, we rely on the rich events from Frida's OkHttp hooks.
        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[NetworkCapture] Subscribed to RuntimeEventBus")

    def _on_event(self, event: Dict[str, Any]) -> None:
        if event.get("category") == "network":
            data = event.get("data", {})
            
            flow = {
                "timestamp": event.get("timestamp", 0),
                "url": data.get("url", ""),
                "method": data.get("method", "GET"),
                "hook": data.get("hook", ""),
                "description": data.get("description", "")
            }
            
            # Basic deduplication for fast-polling malware
            if not any(f.get("url") == flow["url"] and f.get("method") == flow["method"] for f in self.flows):
                self.flows.append(flow)

    def flush(self, output_path: Path) -> int:
        """Write captured flows to JSON."""
        if not self.flows:
            return 0
            
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.flows, f, indent=4)
            logger.info(f"[NetworkCapture] Flushed {len(self.flows)} network flows → {output_path}")
        except Exception as e:
            logger.error(f"[NetworkCapture] Failed to write network.json: {e}")
            
        return len(self.flows)
