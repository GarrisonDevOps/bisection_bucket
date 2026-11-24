# frozen_string_literal: true

# Read-only model for the project_import_export_relation_export_upload_uploads upload partition table.
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
#   while ProjectImportExportRelationExportUploadUploadReplicator handles replication on the secondary.
#
# The composite primary key (id, model_type) is overridden to just `id`
# since `id` is globally unique across all partitions (shared sequence).
# See: https://gitlab.com/gitlab-org/gitlab/-/issues/536647
module Geo
  class ProjectImportExportRelationExportUploadUpload < ::Upload
    include ::Geo::ReplicableModel
    include ::Geo::VerifiableModel
    extend ::Gitlab::Utils::Override

    self.table_name = 'project_import_export_relation_export_upload_uploads'
    self.primary_key = :id

    delegate(*::Geo::VerificationState::VERIFICATION_METHODS,
      to: :project_import_export_relation_export_upload_upload_state)

    with_replicator Geo::ProjectImportExportRelationExportUploadUploadReplicator

    has_one :project_import_export_relation_export_upload_upload_state,
      autosave: false,
      inverse_of: :project_import_export_relation_export_upload_upload,
      class_name: 'Geo::ProjectImportExportRelationExportUploadUploadState'

    scope :project_id_in, ->(ids) { where(project_id: ids) }

    def verification_state_object
      project_import_export_relation_export_upload_upload_state
    end

    def project_import_export_relation_export_upload_upload_state
      super || build_project_import_export_relation_export_upload_upload_state
    end

    class << self
      extend ::Gitlab::Utils::Override

      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

        return replicables unless node.selective_sync?

        if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
          replicables.project_id_in(::Project.selective_sync_scope(node).select(:id))
        elsif node.selective_sync_by_organizations?
          organization_ids = node.organizations.select(:id)
          project_ids = ::Project.where(organization_id: organization_ids).select(:id)
          replicables.where(project_id: project_ids)
        else
          raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
        end
      end

      override :verification_state_model_key
      def verification_state_model_key
        :project_import_export_relation_export_upload_upload_id
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::ProjectImportExportRelationExportUploadUploadState
      end
    end
  end
end
