# frozen_string_literal: true

Analytics::KnowledgeGraph::JwtAuth.ensure_secret! if Gitlab.config.knowledge_graph['enabled']
