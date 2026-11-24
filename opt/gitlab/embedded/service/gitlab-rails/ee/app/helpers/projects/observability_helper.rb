# frozen_string_literal: true

module Projects
  module ObservabilityHelper
    def observability_metrics_view_model(project)
      generate_model(project)
    end

    def observability_metrics_details_view_model(project, metric_id, metric_type)
      generate_model(project) do |model|
        model[:metricId] = metric_id
        model[:metricType] = metric_type
        model[:metricsIndexUrl] = namespace_project_metrics_path(project.group, project)
        model[:createIssueUrl] = new_namespace_project_issue_path(project.group, project)
        model[:tracingIndexUrl] = namespace_project_tracing_index_path(project.group, project)
      end
    end

    def observability_tracing_view_model(project)
      generate_model(project)
    end

    def observability_tracing_details_model(project, trace_id)
      generate_model(project) do |model|
        model[:traceId] = trace_id
        model[:logsIndexUrl] = namespace_project_logs_path(project.group, project)
        model[:createIssueUrl] = new_namespace_project_issue_path(project.group, project)
        model[:metricsIndexUrl] = namespace_project_metrics_path(project.group, project)
      end
    end

    def observability_logs_view_model(project)
      generate_model(project) do |model|
        model[:tracingIndexUrl] = namespace_project_tracing_index_path(project.group, project)
        model[:createIssueUrl] = new_namespace_project_issue_path(project.group, project)
      end
    end

    def observability_usage_quota_view_model(project)
      generate_model(project)
    end

    private

    def generate_model(project)
      model = shared_model(project)

      yield model if block_given?

      ::Gitlab::Json.generate(model)
    end

    def shared_model(project)
      {
        apiConfig: {
          analyticsUrl: ::Gitlab::Observability.analytics_url(project),
          tracingUrl: ::Gitlab::Observability.tracing_url(project),
          tracingAnalyticsUrl: ::Gitlab::Observability.tracing_analytics_url(project),
          servicesUrl: ::Gitlab::Observability.services_url(project),
          operationsUrl: ::Gitlab::Observability.operations_url(project),
          metricsUrl: ::Gitlab::Observability.metrics_url(project),
          metricsSearchUrl: ::Gitlab::Observability.metrics_search_url(project),
          metricsSearchMetadataUrl: ::Gitlab::Observability.metrics_search_metadata_url(project),
          logsSearchUrl: ::Gitlab::Observability.logs_search_url(project),
          logsSearchMetadataUrl: ::Gitlab::Observability.logs_search_metadata_url(project)
        },
        projectFullPath: project.full_path,
        projectId: project.id
      }
    end
  end
end
