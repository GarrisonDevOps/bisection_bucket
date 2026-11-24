# frozen_string_literal: true

module Sbom
  class GraphPath < ::SecApplicationRecord
    include BulkInsertSafe

    belongs_to :ancestor, class_name: 'Sbom::Occurrence', optional: false
    belongs_to :descendant, class_name: 'Sbom::Occurrence', optional: false
    belongs_to :project, class_name: 'Project'

    validates :path_length, presence: true

    scope :by_projects, ->(values) { where(project_id: values) }
    scope :older_than, ->(timestamp) { where(created_at: ...timestamp) }
    scope :by_path_length, ->(path_length) { where(path_length: path_length) }
    scope :by_project_and_timestamp, ->(project_id, created_at) {
      by_projects(project_id).by_path_length(1).where(created_at: created_at)
    }
  end
end
