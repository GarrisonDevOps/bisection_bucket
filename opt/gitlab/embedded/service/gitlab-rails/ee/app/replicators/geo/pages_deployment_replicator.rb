# frozen_string_literal: true

module Geo
  class PagesDeploymentReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::PagesDeployment
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Pages Deployment')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Pages Deployments')
    end

    def carrierwave_uploader
      model_record.file
    end
  end
end
