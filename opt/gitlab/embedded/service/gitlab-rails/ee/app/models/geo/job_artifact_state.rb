# frozen_string_literal: true

module Geo
  class JobArtifactState < Ci::ApplicationRecord
    include ::Geo::VerificationStateDefinition
    include ::Ci::Partitionable

    self.primary_key = :job_artifact_id

    belongs_to :job_artifact,
      ->(artifact_state) { in_partition(artifact_state) },
      inverse_of: :job_artifact_state,
      partition_foreign_key: :partition_id,
      class_name: 'Ci::JobArtifact'

    partitionable scope: :job_artifact
  end
end
