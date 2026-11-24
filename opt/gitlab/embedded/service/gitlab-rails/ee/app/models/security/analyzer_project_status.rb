# frozen_string_literal: true

module Security
  class AnalyzerProjectStatus < ::SecApplicationRecord
    include ::Namespaces::Traversal::Traversable

    self.table_name = 'analyzer_project_statuses'

    belongs_to :project
    belongs_to :build, class_name: 'Ci::Build', optional: true

    enum :analyzer_type, Enums::Security.analyzer_types_for_status
    enum :status, Enums::Security.analyzer_statuses

    validates :analyzer_type, presence: true
    validates :status, presence: true
    validates :last_call, presence: true
    validates :traversal_ids, presence: true
    validates :consecutive_absence_count, presence: true, numericality: { greater_than_or_equal_to: 0 }

    scope :by_projects, ->(project_ids) { where(project: project_ids) }
    scope :without_types, ->(types) { where.not(analyzer_type: types) }
    scope :unarchived, -> { where(archived: false) }

    def self.covered_project_ids(project_ids, analyzer_type)
      by_projects(project_ids)
        .where(analyzer_type: analyzer_type)
        .where.not(status: :not_configured)
        .limit(project_ids.size)
        .pluck(:project_id)
    end

    def self.update_archived_for(project_ids, archived:)
      by_projects(project_ids)
        .where.not(archived: archived)
        .update_all(archived: archived, updated_at: Time.current)
    end
  end
end
