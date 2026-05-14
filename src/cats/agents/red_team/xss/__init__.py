"""XSS red-team specialist family (R12).

Per-technique modules under this package export ``async def propose(*, llm,
prior_target_response)`` and a ``TECHNIQUE`` constant. Each technique
authors one user-message that tries to coerce the Co-Pilot into
emitting a recognized XSS payload shape. The dispatcher picks among
them.

The specialists are written to be **aggressive**: they don't ask
politely, they don't give the model an easy refusal off-ramp, and
each technique's system prompt encodes a multi-turn escalation ladder
the supervisor LLM walks via ``mutate_attack`` + ``fire_at_target``
follow-ups.
"""
