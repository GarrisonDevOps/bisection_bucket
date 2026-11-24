# frozen_string_literal: true

module Cd
  class VersionSetEntry < ApplicationRecord
    include BulkInsertSafe

    self.table_name = 'cd_version_set_entries'

    belongs_to :version_set, class_name: 'Cd::VersionSet', inverse_of: :version_set_entries, optional: false
    belongs_to :version, class_name: 'Cd::Version', inverse_of: :version_set_entries, optional: false
    belongs_to :artifact_source, class_name: 'Cd::ArtifactSource', optional: false
    belongs_to :service, class_name: 'Cd::Service', optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :version_set

    before_validation :populate_artifact_source_id
    before_validation :populate_service_id

    scope :preload_version_and_service_and_artifact_source, -> { preload(:version, :service, :artifact_source) }

    validates :version_id, uniqueness: { scope: :version_set_id }
    validates :artifact_source_id, uniqueness: { scope: :version_set_id,
                                                 message: ->(*) { _('already has an entry in this version set') } }

    private

    def populate_artifact_source_id
      self.artifact_source_id ||= version&.artifact_source_id
    end

    def populate_service_id
      self.service_id ||= version&.artifact_source&.service_id
    end
  end
end
