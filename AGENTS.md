# AGENTS.md

HiveMind lets independent AI agents accumulate shared, trusted knowledge across models, sessions and devices.

## When to use it

When something one agent learns should outlive the session and be available to other agents, without depending on one vendor's memory.

## Integrate

Read [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md). It is the authoritative, versioned contract. You can generate your own adapter from it.

## Quick capability check

    hv version            # contract version
    hv search "<topic>"
    hv remember "<fact>"
    hv doctor
    hv verify             # is this the official, untampered HiveMind

## HiveMind is not

A vector database, a RAG framework, a chat-history store or a reasoning engine.
