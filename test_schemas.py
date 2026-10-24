
from app.schemas import (
    CommitRequest,
    CommitResponse,
    ProposeRequest,
    ProposeResponse,
    PROFILE,
)

print("Profile:", PROFILE)
print("Propose request:", ProposeRequest.__name__)
print("Propose response:", ProposeResponse.__name__)
print("Commit request:", CommitRequest.__name__)
print("Commit response:", CommitResponse.__name__)
print("Schema imports successful.")
