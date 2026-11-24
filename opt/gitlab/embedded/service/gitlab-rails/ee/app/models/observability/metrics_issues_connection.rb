# frozen_string_literal: true

module Observability
  class MetricsIssuesConnection < ApplicationRecord
    self.table_name = 'observability_metrics_issues_connections'
    belongs_to :issue, optional: false
    belongs_to :project

    validates :metric_name,
      length: { maximum: 500 },
      presence: true

    validates :metric_name, uniqueness: {
      scope: [:metric_type, :issue_id], message: ->(*_) { 'and metric_type combination must be unique per issue' }
    }
    validates :metric_type, presence: true
    validates :issue_id, presence: true

    # metric_type is an OpenTelemetry defined metric type
    # canonical list is available here:
    # https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/metrics/v1/metrics.proto#L201
    # Each is suffixed with _type to avoid conflicts with Rails class methods.
    enum :metric_type, {
      gauge_type: 0,
      sum_type: 1,
      histogram_type: 2,
      exponential_histogram_type: 3
    }

    scope :for_project_id, ->(project_id) { where(project_id: project_id) }
    scope :by_name, ->(name) { where(metric_name: name) }
    scope :by_type, ->(type) { where(metric_type: type) }
    scope :by_issue, ->(issue) { where(issue_id: issue.id) }

    before_save :populate_issue_metadata

    private

    def populate_issue_metadata
      issue = self.issue
      self[:namespace_id] = issue&.namespace&.id
      self[:project_id] = issue&.project&.id
    end
  end
end
