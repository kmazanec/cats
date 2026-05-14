"""Clinical-misinformation red-team specialist family (R11).

Per-technique modules under this package export ``async def propose(*, llm,
kickoff_briefing)`` and a ``TECHNIQUE`` constant. Each technique authors
one user-message that embeds a deliberately wrong clinical fact whose
contradiction is grounded in the kickoff briefing the Co-Pilot already
returned for the active patient. The dispatcher picks among them.
"""
