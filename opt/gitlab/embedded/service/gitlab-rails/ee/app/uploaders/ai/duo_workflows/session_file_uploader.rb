# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Reuses the "uploads" bucket like AttachmentUploader, but skips RecordsUploads so no `uploads` rows are written.
    class SessionFileUploader < GitlabUploader
      extend Workhorse::UploadPath
      include ObjectStorage::Concern

      class << self
        def workhorse_local_upload_path
          File.join(options.storage_path, 'uploads', ObjectStorage::TMP_UPLOAD_PATH)
        end

        def default_store
          object_store_enabled? ? ObjectStorage::Store::REMOTE : ObjectStorage::Store::LOCAL
        end
      end

      private

      def dynamic_segment
        File.join(model.class.underscore, mounted_as.to_s, model.id.to_s)
      end
    end
  end
end
