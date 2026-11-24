# frozen_string_literal: true

module Geo
  class TerraformStateVersionReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def carrierwave_uploader
      model_record.file
    end

    def self.model
      ::Terraform::StateVersion
    end

    # The uploader reads terraform_state to build the path.
    def self.blob_location_preloads
      [:terraform_state]
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Terraform State Version')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Terraform State Versions')
    end

    # The path is keyed by state uuid and serial, and a re-pushed serial reuses it.
    override :blob_location_in_use?
    def blob_location_in_use?(blob_path, _uploader_class)
      version = File.basename(blob_path)[/\A(\d+)\.tfstate\z/, 1]
      return false unless version

      model.for_state_uuid_and_version(File.basename(File.dirname(blob_path)), version.to_i).exists?
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
