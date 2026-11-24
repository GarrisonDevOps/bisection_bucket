# frozen_string_literal: true

module Geo
  class PipelineArtifactRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :pipeline_artifact, class_name: '::Ci::PipelineArtifact'

    def self.model_class
      ::Ci::PipelineArtifact
    end

    def self.model_foreign_key
      :pipeline_artifact_id
    end
  end
end
