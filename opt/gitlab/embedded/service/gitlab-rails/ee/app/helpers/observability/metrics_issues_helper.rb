# frozen_string_literal: true

module Observability
  module MetricsIssuesHelper
    def observability_metrics_issues_params(params)
      return {} if params.blank?

      {
        title: "Issue created from #{params['name']}",
        description: observability_metrics_issue_description(params)
      }
    end

    private

    def observability_metrics_issue_description(params)
      description = <<~TEXT
        [Metric details](#{params['fullUrl']}) \\
        Name: `#{params['name']}` \\
        Type: `#{params['type']}` \\
        Timeframe: `#{params.dig('timeframe', 0)} - #{params.dig('timeframe', 1)}`
      TEXT

      if params['imageSnapshotUrl'].present?
        description += <<~TEXT
            | Snapshot |
            | ------ |
            | ![metric_snapshot](#{params['imageSnapshotUrl']}) |
        TEXT
      end

      description
    end
  end
end
