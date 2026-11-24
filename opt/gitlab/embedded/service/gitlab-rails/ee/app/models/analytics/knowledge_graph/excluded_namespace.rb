# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class ExcludedNamespace < ApplicationRecord
      self.table_name = 'knowledge_graph_excluded_namespaces'
      self.primary_key = :root_namespace_id

      belongs_to :namespace, class_name: 'Group',
        foreign_key: :root_namespace_id, inverse_of: :knowledge_graph_excluded_namespace

      validate :only_root_namespaces_can_be_excluded

      scope :for_root_namespace_id, ->(root_namespace_id) { where(root_namespace_id: root_namespace_id) }

      def self.find_or_initialize_for(namespace)
        find_or_initialize_by(root_namespace_id: namespace.id, namespace: namespace)
      end

      def self.remove_for(namespace)
        for_root_namespace_id(namespace.id).delete_all
      end

      private

      def only_root_namespaces_can_be_excluded
        return if namespace&.root?

        errors.add(:base, s_('Orbit|Only top-level groups can be excluded.'))
      end
    end
  end
end
