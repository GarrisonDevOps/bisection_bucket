# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class SessionCapsuleUploader < GitlabUploader
      include ObjectStorage::Concern

      storage_location :duo_session_capsules

      def filename
        'capsule.tar' if original_filename.present? || file.present?
      end

      def store_dir
        dynamic_segment
      end

      class << self
        def default_store
          object_store_enabled? ? ObjectStorage::Store::REMOTE : ObjectStorage::Store::LOCAL
        end

        # Gitlab::Middleware::Multipart rejects Workhorse temp files outside its allowlist, which covers
        # public/uploads/tmp but not the default path under this location's storage_path.
        def workhorse_local_upload_path
          Rails.root.join('public/uploads/tmp/duo_session_capsules').to_s
        end
      end

      private

      def dynamic_segment
        raise ObjectNotReadyError, 'SessionCapsule model not ready' unless model.id && model.namespace_id

        Gitlab::HashedPath.new('session_capsules', model.id, root_hash: model.namespace_id)
      end
    end
  end
end
