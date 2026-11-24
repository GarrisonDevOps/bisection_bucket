# frozen_string_literal: true

module Sbom
  module Ingestion
    module Tasks
      class IngestOccurrenceRefs < Base
        include Gitlab::Utils::StrongMemoize

        self.model = Sbom::OccurrenceRef
        self.unique_by = %i[sbom_occurrence_id security_project_tracked_context_id].freeze
        self.uses = %i[sbom_occurrence_id security_project_tracked_context_id].freeze

        private

        # There may be multiple instances of this task running in parallel, but
        # the UPSERT only inserts a record once. `each_pair` iterates over the
        # rows actually returned by this instance's insert, so we only flag the
        # occurrence maps that correspond to records this instance created.
        def after_ingest
          each_pair { |occurrence_map, _row| occurrence_map.ref_created = true }
        end

        def insert_attributes
          occurrence_maps.filter_map do |occurrence_map|
            # skip if related occurrence has not changed and
            # the occurrence_ref exists with the same reachability
            next if !occurrence_map.occurrence_changed &&
              existing_ref_reachabilities[occurrence_map.occurrence_id] == occurrence_map.reachability

            {
              sbom_occurrence_id: occurrence_map.occurrence_id,
              security_project_tracked_context_id: occurrence_map.security_project_tracked_context_id,
              pipeline_id: pipeline.id,
              project_id: project.id,
              commit_sha: commit_sha,
              reachability: occurrence_map.reachability
            }
          end
        end

        def existing_ref_reachabilities
          occurrence_ids = occurrence_maps.map(&:occurrence_id)
          return {} if occurrence_ids.empty?

          Sbom::OccurrenceRef
            .by_tracked_context(tracked_context_id)
            .by_occurrence(occurrence_ids)
            .pluck(:sbom_occurrence_id, :reachability) # rubocop:disable Database/AvoidUsingPluckWithoutLimit,CodeReuse/ActiveRecord -- operating on a limited batch size
            .to_h
        end
        strong_memoize_attr :existing_ref_reachabilities

        # The tracked context is resolved once per pipeline and stamped onto every
        # occurrence map before ingestion starts, so all maps share the same value.
        def tracked_context_id
          occurrence_maps.first&.security_project_tracked_context_id
        end

        def commit_sha
          pipeline.sha
        end
      end
    end
  end
end
