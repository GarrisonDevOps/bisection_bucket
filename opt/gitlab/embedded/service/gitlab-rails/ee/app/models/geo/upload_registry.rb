# frozen_string_literal: true

module Geo
  class UploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include FromUnion

    extend ::Gitlab::Utils::Override

    self.table_name = 'file_registry'

    belongs_to :upload, foreign_key: :file_id

    scope :fresh, -> { order(created_at: :desc) }

    def self.model_class
      ::Upload
    end

    def self.model_foreign_key
      :file_id
    end

    def self.model_updated_last
      :created_at
    end

    def self.find_registry_differences(range)
      source =
        model_class.replicables_for_current_secondary(range)
            .pluck(model_class.arel_table[:id])

      tracked =
        model_id_in(range)
            .pluck(:file_id)

      untracked = source - tracked
      unused_tracked = tracked - source

      [untracked, unused_tracked]
    end

    def file
      upload&.path || format(_('Removed upload with id %{id}'), id: file_id)
    end

    def project
      upload.model if upload&.model.is_a?(Project)
    end
  end
end
