# frozen_string_literal: true

# Read-only model for the dependency_list_export_part_uploads upload partition table.
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
#   while DependencyListExportPartUploadReplicator handles replication on the secondary.
#
# The composite primary key (id, model_type) is overridden to just `id`
# since `id` is globally unique across all partitions (shared sequence).
# See: https://gitlab.com/gitlab-org/gitlab/-/issues/536647
module Geo
  class DependencyListExportPartUpload < ::Upload
    include ::Geo::ReplicableModel
    include ::Geo::VerifiableModel

    self.table_name = 'dependency_list_export_part_uploads'
    self.primary_key = :id

    delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :dependency_list_export_part_upload_state)

    with_replicator Geo::DependencyListExportPartUploadReplicator

    has_one :dependency_list_export_part_upload_state,
      autosave: false,
      inverse_of: :dependency_list_export_part_upload,
      class_name: 'Geo::DependencyListExportPartUploadState'

    scope :organization_id_in, ->(ids) { where(organization_id: ids) }

    def verification_state_object
      dependency_list_export_part_upload_state
    end

    def dependency_list_export_part_upload_state
      super || build_dependency_list_export_part_upload_state
    end

    class << self
      extend ::Gitlab::Utils::Override

      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

        return replicables unless node.selective_sync?

        if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
          namespace_ids = node.namespaces_for_group_owned_replicables.select(:id)
          organization_ids = ::Namespace.id_in(namespace_ids).distinct(:organization_id).select(:organization_id)
          replicables.organization_id_in(organization_ids)
        elsif node.selective_sync_by_organizations?
          replicables.organization_id_in(node.organizations.select(:id))
        else
          raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
        end
      end

      override :verification_state_model_key
      def verification_state_model_key
        :dependency_list_export_part_upload_id
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::DependencyListExportPartUploadState
      end
    end
  end
end
