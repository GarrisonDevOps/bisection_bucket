# frozen_string_literal: true

Gitlab::Seeder.quiet do
  root_namespace = Group.top_level.first
  next warn "\nSkipping knowledge_graph_excluded_namespaces seeds: no top-level group available" unless root_namespace

  Analytics::KnowledgeGraph::ExcludedNamespace.find_or_create_by!(namespace: root_namespace)

  print '.'
end
