# frozen_string_literal: true

module Vulnerabilities
  class NamespaceStatistic < ::SecApplicationRecord
    include ::Namespaces::Traversal::Traversable

    self.table_name = 'vulnerability_namespace_statistics'

    belongs_to :group, foreign_key: :namespace_id, inverse_of: :vulnerability_namespace_statistic, optional: false
    belongs_to :namespace
    validates :total, numericality: { greater_than_or_equal_to: 0 }
    validates :critical, numericality: { greater_than_or_equal_to: 0 }
    validates :high, numericality: { greater_than_or_equal_to: 0 }
    validates :medium, numericality: { greater_than_or_equal_to: 0 }
    validates :low, numericality: { greater_than_or_equal_to: 0 }
    validates :unknown, numericality: { greater_than_or_equal_to: 0 }
    validates :info, numericality: { greater_than_or_equal_to: 0 }
    validates :traversal_ids, presence: true

    scope :by_namespace, ->(namespace) { where(namespace: namespace) }
  end
end
