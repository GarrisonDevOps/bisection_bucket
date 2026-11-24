# frozen_string_literal: true

module Observability
  class TracesIssuesConnection < ApplicationRecord
    self.table_name = 'observability_traces_issues_connections'
    belongs_to :issue, inverse_of: :observability_traces
    belongs_to :project, inverse_of: :observability_traces
    validates :issue_id, presence: true

    validates :trace_identifier, presence: true, length: { maximum: 128 }

    before_save :populate_sharding_key

    private

    def populate_sharding_key
      issue = self.issue
      self[:project_id] = issue&.project_id
    end
  end
end
