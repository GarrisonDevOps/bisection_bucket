# frozen_string_literal: true

module WorkItems
  module TypesFramework
    class Visibility < ApplicationRecord
      include WorkItems::TypesFramework::HasType

      self.table_name = 'work_item_type_visibilities'

      belongs_to :namespace

      validates :namespace, presence: true
      validates :work_item_type_id, presence: true, uniqueness: { scope: :namespace_id }
      validates :enabled, inclusion: { in: [true, false] }
      validates :propagate, inclusion: { in: [true, false] }

      after_commit :invalidate_provider_cache

      # Returns a { work_item_type_id => enabled } hash for all types that have an
      # explicit override applicable to the given namespace. Missing entries mean
      # "no override" -- callers should default to true (enabled).
      #
      # Resolution rules (single-row schema -- one row per namespace+type):
      # - A row applies if it is an exact self-match (namespace_id = current namespace)
      # - OR it is a propagating ancestor row (propagate = true, namespace_id is an ancestor)
      # - Closest ancestor wins: traversal_ids is [root, ..., current], so we reverse it
      #   and rank by index (0 = current = highest priority).
      def self.resolve_for_namespace(namespace)
        traversal_ids = namespace.traversal_ids

        tuples = traversal_ids.reverse.each_with_index.map { |id, rank| [id, rank] }
        values_sql = Arel::Nodes::ValuesList.new(tuples).to_sql

        rows = joins(
          "JOIN LATERAL (#{values_sql}) AS h(ns_id, rank) ON h.ns_id = namespace_id"
        )
          .where(namespace_id: traversal_ids)
          .where("namespace_id = ? OR propagate = TRUE", namespace.id)
          .select("DISTINCT ON (work_item_type_id) work_item_type_id, enabled")
          .order("work_item_type_id, h.rank ASC")

        rows.each_with_object({}) { |row, map| map[row.work_item_type_id] = row.enabled }
      end

      private

      def invalidate_provider_cache
        ::WorkItems::TypesFramework::Provider.new(namespace).invalidate_cache!
      end
    end
  end
end
