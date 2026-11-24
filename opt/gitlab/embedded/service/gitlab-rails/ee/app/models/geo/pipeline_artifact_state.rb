# frozen_string_literal: true

module Geo
  class PipelineArtifactState < Ci::ApplicationRecord
    include ::Geo::VerificationStateDefinition
    include ::Ci::Partitionable

    self.table_name = 'p_ci_pipeline_artifact_states'
    self.primary_key = :pipeline_artifact_id

    belongs_to :pipeline_artifact,
      ->(artifact_state) { in_partition(artifact_state) },
      inverse_of: :pipeline_artifact_state,
      partition_foreign_key: :partition_id,
      class_name: '::Ci::PipelineArtifact'

    partitionable scope: :pipeline_artifact, partitioned: true
  end
end
