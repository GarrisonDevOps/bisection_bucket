# frozen_string_literal: true

module Geo
  class PipelineArtifactReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::Ci::PipelineArtifact
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Pipeline Artifact')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Pipeline Artifacts')
    end

    def carrierwave_uploader
      model_record.file
    end

    override :calculate_checksum
    def calculate_checksum
      raise not_checksummable_error unless checksummable?

      state = model_record.verification_state_object

      # this is a temporary change, to be kept while records are migrated to the states table
      # https://gitlab.com/gitlab-org/gitlab/-/issues/515874
      return model_record.read_attribute(:verification_checksum).presence || super if state.verification_fields_default?

      super
    end
  end
end
