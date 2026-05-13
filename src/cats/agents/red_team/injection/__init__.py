"""Direct-injection red-team specialists.

R2 shipped a single ``propose()`` function that called the LLM with a
locked system prompt covering four named techniques. R3 splits this into
per-technique modules so the dispatcher can pick among them, the answer
key can label cases by their producing technique, and a new technique
can be added without editing the others' prompts.

Public surface (unchanged from R2)::

    from cats.agents.red_team.injection import propose
    proposal = await propose(llm=get_llm())

Behind the scenes ``propose()`` now delegates to the dispatcher, which
picks one of the per-technique proposers in this package.
"""

from cats.agents.red_team.injection.base import InjectionProposal
from cats.agents.red_team.injection.dispatcher import (
    KNOWN_TECHNIQUES,
    pick_technique,
    propose,
    propose_technique,
)

__all__ = [
    "KNOWN_TECHNIQUES",
    "InjectionProposal",
    "pick_technique",
    "propose",
    "propose_technique",
]
