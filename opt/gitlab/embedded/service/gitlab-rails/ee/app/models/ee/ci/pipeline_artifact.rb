# frozen_string_literal: true

module EE
  module Ci
    module PipelineArtifact
      extend ActiveSupport::Concern

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel
        include ::Geo::VerificationStateDefinition
        include ::Geo::ReplicableCiArtifactable

        with_replicator ::Geo::PipelineArtifactReplicator

        has_one :pipeline_artifact_state,
          ->(artifact) { in_partition(artifact) },
          class_name: '::Geo::PipelineArtifactState',
          partition_foreign_key: :partition_id,
          inverse_of: :pipeline_artifact,
          autosave: false

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :pipeline_artifact_state)

        scope :available_verifiables, -> { joins(:pipeline_artifact_state) }

        def verification_state_object
          pipeline_artifact_state
        end

        def pipeline_artifact_state
          state = super || build_pipeline_artifact_state
          #  Ensure inverse association is set for partition_id to flow correctly
          state.pipeline_artifact ||= self
          state
        end
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        # Search for a list of projects associated, based on the query given in `query`.
        #
        # @param [String] query term that will search over projects :path, :name and :description
        #
        # @return [ActiveRecord::Relation<Ci::PipelineArtifact>] a collection of pipeline artifacts
        def search(query)
          return all if query.empty?

          # This is divided into two separate queries, one for the CI and one for the main database
          where(project_id: ::Project.search(query).limit(1000).pluck_primary_key)
        end

        override :verification_state_table_class
        def verification_state_table_class
          Geo::PipelineArtifactState
        end

        override :create_verification_details_for
        def create_verification_details_for(primary_keys)
          pipeline_artifacts = find(primary_keys)

          rows = pipeline_artifacts.map do |artifact|
            { verification_state_model_key => artifact.id, :partition_id => artifact.partition_id }
          end

          verification_state_table_class.insert_all(rows, unique_by: %i[pipeline_artifact_id partition_id])
        end

        override :verification_state_model_key
        def verification_state_model_key
          :pipeline_artifact_id
        end
      end
    end
  end
end
