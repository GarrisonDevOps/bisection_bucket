# frozen_string_literal: true

module Geo
  class JobArtifactRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    ignore_column :success, remove_with: '15.8', remove_after: '2022-12-22'

    belongs_to :job_artifact, class_name: 'Ci::JobArtifact', foreign_key: :artifact_id

    def self.model_class
      ::Ci::JobArtifact
    end

    def self.model_foreign_key
      :artifact_id
    end
  end
end
