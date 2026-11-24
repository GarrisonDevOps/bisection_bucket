# frozen_string_literal: true

module Security
  module Ingestion
    class TrackedContextFinder
      include Gitlab::Utils::StrongMemoize

      SERVICE_CLASS = Security::ProjectTrackedContexts::FindOrCreateService

      def find_or_create_from_pipeline(pipeline)
        pipeline_cache[pipeline.id] ||= find_or_create_context(SERVICE_CLASS.from_pipeline(pipeline))
      end

      def find_or_create_from_project(project)
        project_cache[project.id] ||= find_or_create_context(SERVICE_CLASS.project_default_branch(project))
      end

      private

      def pipeline_cache
        {}
      end
      strong_memoize_attr :pipeline_cache

      def project_cache
        {}
      end
      strong_memoize_attr :project_cache

      def find_or_create_context(find_or_create_service)
        result = find_or_create_service.execute!

        raise ArgumentError, result.message unless result.success?

        result.payload[:tracked_context]
      end
    end
  end
end
