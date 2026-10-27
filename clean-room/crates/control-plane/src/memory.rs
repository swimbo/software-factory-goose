//! Dynamic codebase memory (R16) — AST knowledge graph + semantic recall.
//!
//! Two halves:
//! - **Graph (deterministic):** `tree-sitter` parses a worktree into `AstGraph` (defines/calls/
//!   imports). Queries like `dependents` / `blast_radius` are pure and feed the qualifier.
//! - **Semantic (fuzzy):** embeddings (via Bifrost) stored in `pgvector` on the existing Postgres,
//!   ANN-searched for convention recall. No Python sidecar.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AstNode {
    pub symbol: String,
    pub kind: String, // fn | struct | trait | mod | …
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AstEdge {
    pub from: String, // symbol
    pub to: String,   // symbol
    pub kind: String, // defines | calls | imports
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AstGraph {
    pub nodes: Vec<AstNode>,
    pub edges: Vec<AstEdge>,
}

/// Symbols that call/import `symbol` — the reverse-dependency set (deterministic, no LLM).
pub fn dependents(graph: &AstGraph, symbol: &str) -> Vec<String> {
    graph
        .edges
        .iter()
        .filter(|e| e.to == symbol && (e.kind == "calls" || e.kind == "imports"))
        .map(|e| e.from.clone())
        .collect()
}

/// Files that depend on anything defined in `file` — the qualifier's blast-radius input.
pub fn blast_radius(graph: &AstGraph, file: &str) -> Vec<String> {
    let defined: Vec<&str> = graph
        .nodes
        .iter()
        .filter(|n| n.file == file)
        .map(|n| n.symbol.as_str())
        .collect();
    let mut files: Vec<String> = graph
        .edges
        .iter()
        .filter(|e| defined.contains(&e.to.as_str()))
        .filter_map(|e| {
            graph
                .nodes
                .iter()
                .find(|n| n.symbol == e.from)
                .map(|n| n.file.clone())
        })
        .collect();
    files.sort();
    files.dedup();
    files
}

/// Parse a Rust source file into graph nodes/edges (R16, tree-sitter).
#[cfg(feature = "ast")]
pub fn parse_rust(source: &str, file: &str) -> AstGraph {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return AstGraph::default();
    }
    let Some(tree) = parser.parse(source, None) else {
        return AstGraph::default();
    };

    let mut graph = AstGraph::default();
    let mut stack = vec![(tree.root_node(), None::<String>)];
    while let Some((node, mut owner)) = stack.pop() {
        let kind = match node.kind() {
            "function_item" => Some("fn"),
            "struct_item" => Some("struct"),
            "trait_item" => Some("trait"),
            "mod_item" => Some("mod"),
            _ => None,
        };
        if let Some(kind) = kind
            && let Some(name) = node.child_by_field_name("name")
        {
            let symbol = name.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            graph.nodes.push(AstNode {
                symbol: symbol.clone(),
                kind: kind.to_string(),
                file: file.to_string(),
            });
            if kind == "fn" {
                owner = Some(symbol);
            }
        }
        // This syntax graph records direct/scoped calls only; it does not pretend to
        // resolve traits, methods, macros, or cross-module symbol identity.
        if node.kind() == "call_expression"
            && let Some(from) = owner.as_ref()
            && let Some(function) = node.child_by_field_name("function")
            && matches!(function.kind(), "identifier" | "scoped_identifier")
            && let Ok(to) = function.utf8_text(source.as_bytes())
            && !graph
                .edges
                .iter()
                .any(|e| e.from == *from && e.to == to && e.kind == "calls")
        {
            graph.edges.push(AstEdge {
                from: from.clone(),
                to: to.to_string(),
                kind: "calls".into(),
            });
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, owner.clone()));
        }
    }
    graph
}

/// Dependents of `symbol`, read from the persisted AST graph (`ast_edges`) — the DB-backed
/// counterpart of the pure `dependents` query, used by the control-plane endpoint.
pub async fn dependents_from_db(pool: &PgPool, symbol: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT from_symbol FROM ast_edges WHERE to_symbol = $1 AND kind IN ('calls','imports')",
    )
    .bind(symbol)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Store an embedding chunk for semantic recall (pgvector).
pub async fn store_embedding(
    pool: &PgPool,
    content: &str,
    vector: &[f32],
    source: &str,
    model: &str,
) -> anyhow::Result<()> {
    // pgvector accepts the `[v1,v2,…]` textual form via a cast.
    let vec_literal = format!(
        "[{}]",
        vector
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    sqlx::query(
        r#"
        INSERT INTO embeddings (id, content, vector, source, model)
        VALUES ($1, $2, $3::vector, $4, $5)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(shared::new_id())
    .bind(content)
    .bind(vec_literal)
    .bind(source)
    .bind(model)
    .execute(pool)
    .await?;
    Ok(())
}

/// ANN-search the nearest stored chunks to `query_vec` (pgvector `<=>` cosine distance).
pub async fn recall(pool: &PgPool, query_vec: &[f32], k: i64) -> anyhow::Result<Vec<String>> {
    let vec_literal = format!(
        "[{}]",
        query_vec
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let rows: Vec<(String,)> =
        sqlx::query_as(r#"SELECT content FROM embeddings ORDER BY vector <=> $1::vector LIMIT $2"#)
            .bind(vec_literal)
            .bind(k)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(c,)| c).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ast")]
    #[test]
    fn rust_parser_connects_direct_calls_to_their_owner() {
        let graph = parse_rust("fn helper() {} fn caller() { helper(); }", "src/lib.rs");
        assert!(
            graph
                .nodes
                .iter()
                .any(|n| n.symbol == "helper" && n.kind == "fn")
        );
        assert_eq!(dependents(&graph, "helper"), vec!["caller"]);
        assert!(dependents(&graph, "caller").is_empty());
    }

    #[cfg(feature = "ast")]
    #[test]
    fn rust_parser_preserves_scoped_calls_and_nested_function_ownership() {
        let graph = parse_rust(
            "fn outer() { fn inner() { tools::run(); } inner(); }",
            "src/lib.rs",
        );
        assert_eq!(dependents(&graph, "tools::run"), vec!["inner"]);
        assert_eq!(dependents(&graph, "inner"), vec!["outer"]);
    }

    fn graph() -> AstGraph {
        AstGraph {
            nodes: vec![
                AstNode {
                    symbol: "alpha".into(),
                    kind: "fn".into(),
                    file: "a.rs".into(),
                },
                AstNode {
                    symbol: "beta".into(),
                    kind: "fn".into(),
                    file: "b.rs".into(),
                },
            ],
            edges: vec![AstEdge {
                from: "beta".into(),
                to: "alpha".into(),
                kind: "calls".into(),
            }],
        }
    }

    #[test]
    fn dependents_returns_callers() {
        assert_eq!(dependents(&graph(), "alpha"), vec!["beta".to_string()]);
        assert!(dependents(&graph(), "beta").is_empty());
    }

    #[test]
    fn blast_radius_returns_dependent_files() {
        assert_eq!(blast_radius(&graph(), "a.rs"), vec!["b.rs".to_string()]);
        assert!(blast_radius(&graph(), "b.rs").is_empty());
    }

    #[test]
    fn defines_edges_are_not_dependents() {
        let g = AstGraph {
            nodes: vec![],
            edges: vec![AstEdge {
                from: "f".into(),
                to: "x".into(),
                kind: "defines".into(),
            }],
        };
        assert!(dependents(&g, "x").is_empty());
    }
}
