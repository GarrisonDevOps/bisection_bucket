# frozen_string_literal: true

module Geo
  class PackagesHelmMetadataCacheState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :packages_helm_metadata_cache, inverse_of: :packages_helm_metadata_cache_state,
      class_name: 'Packages::Helm::MetadataCache'

    validates :verification_state, :packages_helm_metadata_cache, presence: true
  end
end
