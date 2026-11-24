# frozen_string_literal: true

module Cd
  class ArtifactSource < ApplicationRecord
    self.table_name = 'cd_artifact_sources'

    belongs_to :service, class_name: 'Cd::Service', inverse_of: :artifact_sources, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :versions, class_name: 'Cd::Version', inverse_of: :artifact_source

    populate_sharding_key :organization_id, source: :service

    scope :for_source_ref, ->(source_ref) { where(source_ref: source_ref) }
    scope :in_organization, ->(organization) { where(organization_id: organization) }

    validates :name, presence: true, length: { maximum: 255 }
    validates :source_ref, presence: true, length: { maximum: 255 }
    validates :source_config, json_schema: { filename: 'cd_artifact_source_config', size_limit: 64.kilobytes }
  end
end
