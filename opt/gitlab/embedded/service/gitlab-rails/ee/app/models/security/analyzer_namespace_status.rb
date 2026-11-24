# frozen_string_literal: true

module Security
  class AnalyzerNamespaceStatus < ::SecApplicationRecord
    include ::Namespaces::Traversal::Traversable

    self.table_name = 'analyzer_namespace_statuses'

    belongs_to :group, foreign_key: :namespace_id, inverse_of: :analyzer_group_statuses
    belongs_to :namespace

    enum :analyzer_type, Enums::Security.analyzer_types_for_status

    validates :success, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :failure, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :stale, presence: true, numericality: { greater_than_or_equal_to: 0 }
    validates :analyzer_type, presence: true
    validates :traversal_ids, presence: true

    scope :by_namespace, ->(namespace) { where(namespace_id: namespace) }

    def self.status_for(namespace, analyzer_type)
      by_namespace(namespace).find_by(analyzer_type: analyzer_type)
    end

    def total_projects_count
      @total_projects_count ||= group.all_unarchived_project_ids.size
    end

    def not_configured
      [total_projects_count - success - failure - stale, 0].max
    end
  end
end
