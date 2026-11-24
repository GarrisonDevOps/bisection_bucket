# frozen_string_literal: true

module Observability
  class LogsIssuesConnection < ApplicationRecord
    self.table_name = 'observability_logs_issues_connections'
    belongs_to :issue, inverse_of: :observability_logs
    belongs_to :project, inverse_of: :observability_logs

    validates :issue_id, presence: true

    validates :service_name, presence: true, length: { maximum: 500 }

    # https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
    validates :severity_number,
      presence: true,
      numericality: { only_integer: true, greater_than_or_equal_to: 1, less_than_or_equal_to: 24 }

    validates :log_timestamp, presence: true
    validates :trace_identifier, presence: true, length: { maximum: 128 }
    validates :log_fingerprint, presence: true, length: { maximum: 128 }

    before_save :populate_sharding_key

    scope :with_params, ->(params) do
      where(log_timestamp: params[:timestamp],
        service_name: params[:service_name],
        severity_number: params[:severity_number],
        trace_identifier: params[:trace_identifier],
        log_fingerprint: params[:fingerprint]
      )
    end

    private

    def populate_sharding_key
      issue = self.issue
      self[:project_id] = issue&.project_id
    end
  end
end
