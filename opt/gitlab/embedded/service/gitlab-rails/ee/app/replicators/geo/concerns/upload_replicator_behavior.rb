# frozen_string_literal: true

module Geo
  module Concerns
    # Shared behaviour for replicators backed by Upload or upload partition
    # models (e.g. Geo::AbuseReportUpload, Geo::ProjectUpload).
    #
    # Implements BlobReplicatorStrategy's abstract carrierwave_uploader (every
    # Upload-backed model resolves it the same way), plus two overrides:
    #
    # 1. Model-ownership validation: Upload models carry a polymorphic `model`
    #    association. If the owning record has been deleted, attempting to build
    #    file paths raises an opaque exception. `predownload_validation_failure`
    #    and `calculate_checksum` intercept that case early and surface a clear
    #    error message.
    #
    # 2. Parent-checksum adoption: Upload partition models share a row in
    #    Geo::UploadState with their parent Upload. When the parent has already
    #    been verified, the first verification on each site returns the stored
    #    checksum instead of re-reading and re-hashing the file, avoiding
    #    redundant I/O when a partition replicator FF is first enabled.
    #    Reverification always reads the file.
    #
    # 3. Skip-download gating: on a secondary, a new registry skips the
    #    download only if the checksum will not be adopted, or if the legacy
    #    registry already verified this site's copy.
    module UploadReplicatorBehavior
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      class_methods do
        # FileUploader and the avatar uploaders build their path from the owner.
        def blob_location_preloads
          [:model]
        end

        # Upload partition models inherit from ::Upload (strict subclass), while the
        # legacy Geo::UploadReplicator's model is ::Upload itself, so it is excluded.
        def replicable_group
          'uploads' if model < ::Upload
        end

        def replicable_group_title
          s_('Geo|Uploads') if replicable_group
        end

        def replicable_group_description
          s_('Geo|Uploads are replicated by type. Select a type to review its replication status.') if replicable_group
        end
      end

      # Every Upload-backed replicable resolves its CarrierWave uploader the
      # same way, so implement BlobReplicatorStrategy's abstract
      # carrierwave_uploader here instead of redefining it in each replicator.
      def carrierwave_uploader
        model_record.retrieve_uploader
      end

      override :stored_uploader_class
      def stored_uploader_class(registry)
        registry.uploader_class
      end

      # RecordsUploads#readd_upload replaces an Upload at the same uploader and path without a delete event.
      # Only uploaders that store the full relative path in Upload#path (like avatars) can match. FileUploader
      # stores `secret/filename`, and its random secret means the path is never reused.
      override :blob_location_in_use?
      def blob_location_in_use?(blob_path, uploader_class)
        model.for_uploader_and_path(uploader_class, blob_path).exists?
      end

      # Upload partitions cascade-delete on their sharding key, but other owners can disappear.
      # Building the path of such an upload raises, so return no location instead of tracking an error.
      override :registry_blob_location
      def registry_blob_location
        return { blob_path: nil, uploader_class: nil } if model_is_missing_error_message

        super
      end

      # Do not attempt download unless the upload's owner `model` is present.
      # Otherwise, attempting to build file paths will raise an exception.
      def predownload_validation_failure
        error_message = model_is_missing_error_message
        return error_message if error_message

        super
      end

      def calculate_checksum
        error_message = model_is_missing_error_message
        raise error_message if error_message

        # Upload partition models inherit from Upload, which has a has_one
        # :upload_state association pointing to Geo::UploadState. If the parent
        # upload has already been verified, adopt its checksum directly instead
        # of re-reading and re-hashing the file. Uploads are immutable in
        # GitLab, so the parent's checksum is always valid for the partition.
        #
        # See: https://gitlab.com/gitlab-org/gitlab/-/work_items/594341
        return model_record.upload_state.verification_checksum if parent_upload_verification_succeeded?

        super
      end

      # Returns true when the parent Upload's verification state has succeeded
      # and the replicable is immutable, meaning its checksum can be safely
      # adopted by the partition replicator without risk of stale data.
      def parent_upload_verification_succeeded?
        return false unless immutable? && model_record.upload_state
        # Adopt only on the first verification on this site. Reverification must
        # read the file, or damage after the first checksum is never found.
        return false unless verification_state_tracker.verified_at.nil?

        model_record.upload_state.verification_succeeded?
      end

      def model_is_missing_error_message
        return if model_record.model.present?

        "The model which owns this #{replicable_name} is missing. " \
          "#{replicable_name} ID##{model_record.id}, #{model_record.model_type} ID##{model_record.model_id}"
      end

      private

      # Skipping the download is safe only if something reads this site's copy.
      # Adopting the parent checksum never reads it, so fall back to the legacy registry.
      def skip_download_can_rely_on_verification?
        return false unless super
        return true unless parent_upload_verification_succeeded?

        ::Geo::UploadRegistry.for_model_record_id(model_record.id).verification_succeeded?
      end
    end
  end
end
