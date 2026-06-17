# Requirements Specification: mango-parental-control

This document details the functional and non-functional requirements for the **mango-parental-control** microservice.

---

## 1. Executive Summary

Provide a 1-2 sentence overview of why this service is being created and what problem it solves in the Mango Cloud ecosystem.

---

## 2. Scope of Work

### What the Service WILL Do:
* [Example] Store item data in a PostgreSQL schema.
* [Example] Expose standard REST endpoints for item management.
* [Example] Register itself with OpenWiFi Service Discovery.
* [ ]

### What the Service WILL NOT Do:
* [Example] Authenticate users directly (delegated to `owsec`).
* [Example] Route web traffic directly (delegated to load balancers).
* [ ]

---

## 3. User Stories & Functional Scopes

### User Story 1: [Short Title]
* **As a** [role/service]
* **I want to** [action]
* **So that** [benefit/outcome]

**Acceptance Criteria:**
- [ ] Criterion A
- [ ] Criterion B

---

## 4. Interfaces & Integrations

List other services in the mesh this service will communicate with (e.g. `owsec`, `owsub`, `owgw`).

| Target Service | Integration Type | Description |
|---|---|---|
| `owsec` | HTTP REST/RPC | Session verification and token validity checks |
| | | |

---

## 5. Security & Access Control

Define access levels required for the endpoints (e.g. public authentication, internal API keys only).

* **Internal Routing Access**: Private ports (`17xxx`) must be restricted to internal container-to-container calls using the `X-API-KEY`.
* **Public User Access**: Public ports (`16xxx`) must require a valid Bearer Token validated by the security client.

---

## 6. Constraints & Non-Functional Requirements

* **Performance**: Target latency budgets (e.g. 95th percentile under 50ms).
* **Storage Limit**: Approximate database footprint/growth expectation.
* **Compliance**: GDPR, logging redaction constraints.
