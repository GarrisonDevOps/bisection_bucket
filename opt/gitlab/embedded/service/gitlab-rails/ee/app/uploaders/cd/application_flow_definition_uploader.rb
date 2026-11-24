# frozen_string_literal: true

module Cd
  class ApplicationFlowDefinitionUploader < GitlabUploader
    include ObjectStorage::Concern

    storage_location :uploads

    def store_dir
      File.join(base_dir, dynamic_segment)
    end

    def filename
      'definition.yml' if original_filename.present? || file.present?
    end

    private

    def dynamic_segment
      raise ObjectNotReadyError, 'ApplicationFlowDefinition model not ready' unless model.id && model.organization_id

      Gitlab::HashedPath.new('cd_application_flow_definitions', model.id, root_hash: model.organization_id)
    end

    class << self
      def default_store
        object_store_enabled? ? ObjectStorage::Store::REMOTE : ObjectStorage::Store::LOCAL
      end
    end
  end
end
