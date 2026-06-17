# Service Design: mango-parental-control

This document details the architectural layout, database models, and internal logic flows for the **mango-parental-control** microservice.

---

## 1. High-Level Architecture

Provide a text or Mermaid diagram showing how data flows between callers (e.g. `owsub`), this service, and the database.

```text
[External Caller] ---> (Public Port) ---> [http.Module] ---> [handlers]
                                                                  |
                                                                  v
[DB Engine] <=== (pgxpool) === [db.Database] <--- [services] <----+
```

---

## 2. Logical Data Model

Describe the core data entities and their relations (e.g., one-to-many, many-to-many relationships).

---

## 3. Database Schema

Detail the SQL table schemas that will be added to `db/schema/` for startup migration.

### Table: `sample_items`
```sql
CREATE TABLE IF NOT EXISTS sample_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. REST API Endpoints Contract

List the endpoints exposed by the service, their input structures, and output envelopes. Refer to `openapi.yaml` for full spec definitions.

---

## 5. Background Routines & Concurrency

Detail any background tickers, Kafka consumer group listeners, or async jobs run by this service.

---

## 6. Error Codes Matrix

Document all custom errors returned by the service under the `apperror` codes.

| Code Name | HTTP Status | Description |
|---|---|---|
| `CodeNotFound` | 404 | The requested item ID was not found in the database. |
| `CodeInvalidInput` | 400 | Request body failed structural validation. |
| `CodeInternal` | 500 | Database connection pool or filesystem failure. |
