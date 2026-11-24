# frozen_string_literal: true

module EE
  module Gitlab
    module Observability
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      class_methods do
        def analytics_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/analytics/storage"
        end

        def tracing_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/traces"
        end

        def tracing_analytics_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/traces/analytics"
        end

        def services_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/services"
        end

        def operations_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/services/$SERVICE_NAME$/operations"
        end

        def metrics_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/metrics/autocomplete"
        end

        def metrics_search_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/metrics/search"
        end

        def metrics_search_metadata_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/metrics/searchmetadata"
        end

        def logs_search_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/logs/search"
        end

        def logs_search_metadata_url(project)
          "/api/v4/projects/#{project.id}/observability/v1/logs/searchmetadata"
        end
      end
    end
  end
end
