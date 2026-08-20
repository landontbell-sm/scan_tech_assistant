from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class Outcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation: str
    meaning: str
    next_action: str

class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order: int
    title: str
    explanation: str
    command: str | None
    payload_origin: Literal["plugin", "model_designed"] | None = None
    outcomes: list[Outcome] = Field(default_factory=list)

class ProcedureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[Step]
    note: str = ""
