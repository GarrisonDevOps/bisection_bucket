# frozen_string_literal: true

module Security
  module NamespaceTraversalSqlBuilder
    private

    # rubocop:disable CodeReuse/ActiveRecord -- Centralized namespace data extraction
    def pluck_namespace_ids_and_traversal_ids(relation, limit: ApplicationRecord::MAX_PLUCK)
      relation.limit(limit).pluck(:id, :traversal_ids)
    end
    # rubocop:enable CodeReuse/ActiveRecord

    def with_namespace_data(namespace_ids_batch)
      return unless namespace_ids_batch.present?

      namespace_values = pluck_namespace_ids_and_traversal_ids(
        Namespace.not_deletion_in_progress.without_project_namespaces
          .id_in(namespace_ids_batch)
          .limit(namespace_ids_batch.length)
      )
      return unless namespace_values.present?

      namespaces_and_traversal_ids_query_values(namespace_values)
    end

    def namespaces_and_traversal_ids_query_values(namespaces_and_traversal_ids)
      values = namespaces_and_traversal_ids.map do |namespace_id, traversal_ids|
        validated_namespace_id = Integer(namespace_id)
        validated_traversal_ids = traversal_ids.map { |id| Integer(id) }
        validated_next_traversal_ids = validated_traversal_ids.dup.tap { |ids| ids[-1] += 1 }

        [
          validated_namespace_id,
          Arel.sql("ARRAY#{validated_traversal_ids}::bigint[]"),
          Arel.sql("ARRAY#{validated_next_traversal_ids}::bigint[]")
        ]
      end

      Arel::Nodes::ValuesList.new(values).to_sql
    end
  end
end
