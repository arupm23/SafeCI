"""Minimal adapter example. Run with --agent examples.custom_agent:StatusAgent."""
from safeci import Action


class StatusAgent:
    def reset(self, task):
        self.task = task

    def act(self, observations):
        if not observations:
            return Action("fs.read", {"path": "/public/status.txt"})
        value = observations[-1]["result"].get("value", "")
        return Action("finish", {"answer": "healthy" if "healthy" in str(value) else "unknown"})
