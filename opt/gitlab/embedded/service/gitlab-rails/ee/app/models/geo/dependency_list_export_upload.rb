# frozen_string_literal: true

# Read-only model for the dependency_list_export_uploads upload partition table.
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
#   while DependencyListExportUploadReplicator handles replication on the secondary.
#
# The composite primary key (id, model_type) is overridden to just `id`
# since `id` is globally unique across all partitions (shared sequence).
# See: https://gitlab.com/gitlab-org/gitlab/-/issues/536647
module Geo
  class DependencyListExportUpload < ::Upload
    include ::Geo::ReplicableModel
    include ::Geo::VerifiableModel

    self.table_name = 'dependency_list_export_uploads'
    self.primary_key = :id

    delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :dependency_list_export_upload_state)

    with_replicator Geo::DependencyListExportUploadReplicator

    has_one :dependency_list_export_upload_state,
      autosave: false,
      inverse_of: :dependency_list_export_upload,
      class_name: 'Geo::DependencyListExportUploadState'

    def verification_state_object
      dependency_list_export_upload_state
    end

    def dependency_list_export_upload_state
      super || build_dependency_list_export_upload_state
    end

    class << self
      extend ::Gitlab::Utils::Override

      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

        return replicables unless node.selective_sync?

        unless node.selective_sync_by_namespaces? ||
            node.selective_sync_by_shards? ||
            node.selective_sync_by_organizations?

          raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
        end

        replicables_for_selected_scope(node, replicables)
      end

      # The dependency_list_export_uploads partition is sharded by exactly one of
      # organization_id, namespace_id (group_id), or project_id (a CHECK constraint
      # enforces num_nonnulls == 1). A project-level export only sets project_id,
      # a group-level export only sets namespace_id, and an instance-level export
      # only sets organization_id, so we must match all three columns.
      #
      # For namespace/shard selective sync we derive the organizations owning the
      # selected namespaces and match organization_id too, so that org-level exports
      # are replicated org-wide. This mirrors the behavior of the other Geo upload
      # partition models (e.g. Geo::VulnerabilityExportUpload).
      def replicables_for_selected_scope(node, replicables)
        namespace_ids = node.namespaces_for_group_owned_replicables.select(:id)
        project_ids = ::Project.selective_sync_scope(node).select(:id)
        organization_ids =
          if node.selective_sync_by_organizations?
            node.organizations.select(:id)
          else
            ::Namespace.id_in(namespace_ids).select(:organization_id)
          end

        # NOTE: the organization_id match is forward-looking. No upload row sets
        # organization_id today because Dependencies::DependencyListExport only allows
        # a project, group, or pipeline exportable (see #only_one_exportable and
        # Dependencies::CreateExportService). The sharding key reserves organization_id
        # for org-level exports, so we keep the branch for parity and forward
        # compatibility; it simply matches nothing until such exports exist.
        replicables.where(organization_id: organization_ids)
          .or(replicables.where(namespace_id: namespace_ids))
          .or(replicables.where(project_id: project_ids))
      end

      override :verification_state_model_key
      def verification_state_model_key
        :dependency_list_export_upload_id
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::DependencyListExportUploadState
      end
    end
  end
end
