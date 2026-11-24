# frozen_string_literal: true

module Observability
  module IssueLinks
    class CreateService < BaseService
      METRICS_ATTRS = [:metric_details_name, :metric_details_type].freeze
      LOGS_ATTRS = [:log_service_name, :log_severity_number, :log_timestamp, :log_fingerprint, :log_trace_id].freeze
      TRACES_ATTRS = [:trace_id].freeze

      def execute
        return ServiceResponse.error(message: 'No permission') unless allowed?

        issue = @params[:issue]
        links = @params[:links]
        return ServiceResponse.success unless links.present?

        if all_keys_present?(links, METRICS_ATTRS)
          persist_metrics_links(issue, links)
        elsif all_keys_present?(links, LOGS_ATTRS)
          persist_logs_links(issue, links)
        elsif all_keys_present?(links, TRACES_ATTRS)
          persist_traces_links(issue, links)
        else
          ServiceResponse.error(message: 'Insufficient link params')
        end
      end

      private

      def allowed?
        Ability.allowed?(current_user, :read_observability, project)
      end

      def all_keys_present?(params, keys)
        params.values_at(*keys).all?(&:present?)
      end

      def persist_metrics_links(issue, links)
        begin
          ::Observability::MetricsIssuesConnection.create!(
            metric_name: links[:metric_details_name],
            metric_type: links[:metric_details_type],
            issue: issue
          )
        rescue ActiveRecord::RecordInvalid => e
          return ServiceResponse.error(message: e.message)
        end

        ServiceResponse.success
      end

      def persist_logs_links(issue, links)
        begin
          ::Observability::LogsIssuesConnection.create!(
            service_name: links[:log_service_name],
            severity_number: links[:log_severity_number],
            log_timestamp: links[:log_timestamp],
            log_fingerprint: links[:log_fingerprint],
            trace_identifier: links[:log_trace_id],
            issue: issue
          )
        rescue ActiveRecord::RecordInvalid => e
          return ServiceResponse.error(message: e.message)
        end

        ServiceResponse.success
      end

      def persist_traces_links(issue, links)
        begin
          ::Observability::TracesIssuesConnection.create!(
            trace_identifier: links[:trace_id],
            issue: issue
          )
        rescue ActiveRecord::RecordInvalid => e
          return ServiceResponse.error(message: e.message)
        end

        ServiceResponse.success
      end
    end
  end
end
