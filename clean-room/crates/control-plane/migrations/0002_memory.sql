-- R16 memory: AST knowledge graph + pgvector semantic layer, on the existing Postgres.
-- Requires the `pgvector` extension (switch the compose image to `pgvector/pgvector:pg16`).

CREATE EXTENSION IF NOT EXISTS vector;

-- AST knowledge graph (deterministic; rebuilt per git revision).
CREATE TABLE IF NOT EXISTS ast_nodes (
    id           TEXT PRIMARY KEY,
    symbol       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    file         TEXT NOT NULL,
    git_revision TEXT
);

CREATE TABLE IF NOT EXISTS ast_edges (
    from_symbol TEXT NOT NULL,
    to_symbol   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    PRIMARY KEY (from_symbol, to_symbol, kind)
);

CREATE INDEX IF NOT EXISTS idx_ast_edges_to ON ast_edges (to_symbol);
CREATE INDEX IF NOT EXISTS idx_ast_nodes_file ON ast_nodes (file);

-- Semantic layer (fuzzy recall; embeddings come from Bifrost). The dimension matches the
-- embedding model in use — adjust to the model's output dimension.
CREATE TABLE IF NOT EXISTS embeddings (
    id         TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    vector     vector(1536),
    source     TEXT,
    model      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_embeddings_vec ON embeddings USING hnsw (vector vector_cosine_ops);
