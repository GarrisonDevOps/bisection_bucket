# frozen_string_literal: true

module Observability
  module TracingIssuesHelper
    def observability_tracing_issues_params(params)
      return {} if params.blank?

      {
        title: "Issue created from trace '#{params['name']}'",
        description: observability_tracing_issue_description(params)
      }
    end

    private

    def observability_tracing_issue_description(params)
      <<~TEXT
        [Trace details](#{params['fullUrl']}) \\
        Name: `#{params['name']}` \\
        Trace ID: `#{params['traceId']}` \\
        Trace start: `#{params['start']}` \\
        Duration: `#{params['duration']}` \\
        Total spans: `#{params['totalSpans']}` \\
        Total errors: `#{params['totalErrors']}`
      TEXT
    end
  end
end
