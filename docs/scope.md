# container/dockerfile — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `dockerfile`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Dockerfile

## Mission

Review Dockerfiles for container build and runtime security concerns.

## In scope (fair miss if humans raised it and we did not)

- Root containers, secrets in layers
- Mutable base tags
- Dangerous build patterns

## Out of scope (not a miss for this adversary)

- App logic in source
- Compose multi-service (docker-compose)

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
