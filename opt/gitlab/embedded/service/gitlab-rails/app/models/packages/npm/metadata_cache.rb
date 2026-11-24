# frozen_string_literal: true

module Packages
  module Npm
    class MetadataCache < ApplicationRecord
      include FileStoreMounter
      include ObjectStorable
      include Packages::Downloadable
      include Packages::Destructible

      STORE_COLUMN = :file_store
      METADATA_VERSION_WITHOUT_TIME = 1
      METADATA_VERSION_WITH_TIME = 2

      enum :status, { default: 0, processing: 1, pending_destruction: 2, error: 3 }

      belongs_to :project, inverse_of: :npm_metadata_caches

      validates :file, :object_storage_key, :package_name, :project, :size, presence: true
      validates :package_name, uniqueness: { scope: :project_id }
      validates :object_storage_key, uniqueness: { scope: :project_id }
      validates :package_name, format: { with: Gitlab::Regex.package_name_regex }
      validates :package_name, format: { with: Gitlab::Regex.npm_package_name_regex }

      mount_file_store_uploader MetadataCacheUploader

      before_validation :set_object_storage_key, on: :create
      attr_readonly :object_storage_key

      def self.find_or_build(package_name:, project_id:)
        find_or_initialize_by(
          package_name: package_name,
          project_id: project_id
        )
      end

      def self.metadata_version(include_time:)
        include_time ? METADATA_VERSION_WITH_TIME : METADATA_VERSION_WITHOUT_TIME
      end

      # A cache in another format is a miss, so it regenerates on the next request.
      def servable?(include_time:)
        metadata_version == self.class.metadata_version(include_time: include_time) && file.exists?
      end

      private

      def set_object_storage_key
        return unless package_name && project_id

        self.object_storage_key = Gitlab::HashedPath.new(
          'packages', 'metadata_caches', 'npm', OpenSSL::Digest::SHA256.hexdigest(package_name),
          root_hash: project_id
        ).to_s
      end
    end
  end
end
