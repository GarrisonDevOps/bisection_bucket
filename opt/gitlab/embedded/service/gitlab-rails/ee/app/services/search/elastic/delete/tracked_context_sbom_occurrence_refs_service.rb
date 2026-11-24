# frozen_string_literal: true

module Search
  module Elastic
    module Delete
      # Deletes sbom_occurrence_ref documents for a single tracked context from the
      # Elasticsearch index
      # Requires both project_id and security_project_tracked_context_id.
      class TrackedContextSbomOccurrenceRefsService < BaseService
        private

        def build_query
          project_id = options[:project_id]
          security_project_tracked_context_id = options[:security_project_tracked_context_id]

          if project_id.nil? || security_project_tracked_context_id.nil?
            Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
              ArgumentError.new('project_id and security_project_tracked_context_id are required')
            )
            return
          end

          {
            query: {
              bool: {
                filter: [
                  { term: { project_id: project_id } },
                  { term: { security_project_tracked_context_id: security_project_tracked_context_id } }
                ]
              }
            }
          }
        end

        def index_name
          ::Search::Elastic::Types::Sbom::OccurrenceRef.index_name
        end
      end
    end
  end
end
