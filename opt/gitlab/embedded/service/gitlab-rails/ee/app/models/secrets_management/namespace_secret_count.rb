# frozen_string_literal: true

module SecretsManagement
  class NamespaceSecretCount < ApplicationRecord
    self.table_name = 'namespace_secret_counts'
    self.primary_key = :namespace_id

    belongs_to :namespace, optional: false
    belongs_to :root_namespace, class_name: 'Namespace', optional: false

    validates :count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }

    scope :for_root_namespace, ->(root_namespace_id) { where(root_namespace_id: root_namespace_id) }
    scope :for_namespace_id, ->(namespace_id) { where(namespace_id: namespace_id) }
    scope :distinct_root_namespace_ids, -> { select(:root_namespace_id).distinct }
  end
end
