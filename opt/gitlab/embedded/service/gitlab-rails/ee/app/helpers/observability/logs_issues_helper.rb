# frozen_string_literal: true

module Observability
  module LogsIssuesHelper
    def observability_logs_issues_params(params)
      return {} if params.blank?

      {
        title: "Issue created from log of '#{params['service']}' service at #{params['timestamp']}",
        description: observability_logs_issue_description(params)
      }
    end

    private

    def observability_logs_issue_description(params)
      <<~TEXT
        [Log details](#{params['fullUrl']}) \\
        Service: `#{params['service']}` \\
        Trace ID: `#{params['traceId']}` \\
        Log Fingerprint: `#{params['fingerprint']}` \\
        Severity Number: `#{params['severityNumber']}` \\
        Timestamp: `#{params['timestamp']}` \\
        Message:
        ```
        #{params['body']}
        ```
      TEXT
    end
  end
end
