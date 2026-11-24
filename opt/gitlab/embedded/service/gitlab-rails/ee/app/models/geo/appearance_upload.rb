# frozen_string_literal: true

# Read-only model for the appearance_uploads upload partition table.
#
# Upload partition tables are populated automatically by PostgreSQL's
# list partitioning on model_type. The application writes through the
# Upload model to the uploads parent table, and PostgreSQL routes the
# row to the correct partition.
#
# This model reads from the partition table for Geo replication. It
# inherits from Upload to get all Upload behavior (retrieve_uploader,
# model polymorphic association, absolute_path, etc.).
#
# Dual-path architecture:
#
# - Upload includes Geo::ReplicableModel, so after_create_commit fires
#   geo_create_event! via Geo::UploadReplicator for all upload types.
# - This model also includes Geo::ReplicableModel, but since records are
#   never "created" via this model, callbacks don't fire.
# - The save_partition_verification_details callback in EE::Upload
#   correctly writes verification state to the partition state table.
# - Geo events flow through UploadReplicator for all uploads (including this one),
#   while AppearanceUploadReplicator handles replication on the secondary.
#
# The composite primary key (id, model_type) is overridden to just `id`
# since `id` is globally unique across all partitions (shared sequence).
# See: https://gitlab.com/gitlab-org/gitlab/-/issues/536647
module Geo
  class AppearanceUpload < ::Upload
    include ::Geo::ReplicableModel
    include ::Geo::VerifiableModel

    self.table_name = 'appearance_uploads'
    self.primary_key = :id

    delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :appearance_upload_state)

    with_replicator Geo::AppearanceUploadReplicator

    has_one :appearance_upload_state,
      autosave: false,
      inverse_of: :appearance_upload,
      class_name: 'Geo::AppearanceUploadState'

    def verification_state_object
      appearance_upload_state
    end

    def appearance_upload_state
      super || build_appearance_upload_state
    end

    class << self
      extend ::Gitlab::Utils::Override

      override :selective_sync_scope
      def selective_sync_scope(_node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

        # Instance-wide cell-setting replicables have no organization, namespace, or
        # project, so they are always replicated regardless of the node's selective
        # sync configuration.
        replicables
      end

      override :verification_state_model_key
      def verification_state_model_key
        :appearance_upload_id
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::AppearanceUploadState
      end
    end
  end
end
