# frozen_string_literal: true

module Observability
  module ObservabilityIssuesHelper
    include ::Observability::MetricsIssuesHelper
    include ::Observability::LogsIssuesHelper
    include ::Observability::TracingIssuesHelper

    def gather_observability_values(params)
      if params[:observability_metric_details].present?
        parsed = ::Gitlab::Json.safe_parse(CGI.unescape(params[:observability_metric_details]))

        { metric: { name: parsed['name'], type: "#{parsed['type'].downcase}_type" } }
      elsif params[:observability_log_details].present?
        parsed = ::Gitlab::Json.safe_parse(CGI.unescape(params[:observability_log_details]))

        {
          log: {
            service: parsed['service'],
            severityNumber: parsed['severityNumber'],
            fingerprint: parsed['fingerprint'],
            timestamp: parsed['timestamp'],
            traceId: parsed['traceId']
          }
        }
      elsif params[:observability_trace_details].present?
        parsed = ::Gitlab::Json.safe_parse(CGI.unescape(params[:observability_trace_details]))

        {
          trace: {
            traceId: parsed['traceId']
          }
        }
      end
    end

    def observability_issue_params
      return {} unless can?(current_user, :read_observability, container)

      links_params = parsed_link_params(params[:observability_links])

      if links_params[:metrics].present?
        observability_metrics_issues_params(links_params[:metrics])
      elsif links_params[:logs].present?
        observability_logs_issues_params(links_params[:logs])
      elsif links_params[:tracing].present?
        observability_tracing_issues_params(links_params[:tracing])
      else
        {}
      end
    end

    private

    def parsed_link_params(links_params)
      return {} unless links_params.present?

      {
        metrics: safe_parse_json(links_params[:metrics]),
        logs: safe_parse_json(links_params[:logs]),
        tracing: safe_parse_json(links_params[:tracing])
      }
    end

    def safe_parse_json(stringified_json)
      return {} if stringified_json.blank?

      ::Gitlab::Json.safe_parse(CGI.unescape(stringified_json))
    rescue JSON::ParserError, TypeError
      {}
    end
  end
end
