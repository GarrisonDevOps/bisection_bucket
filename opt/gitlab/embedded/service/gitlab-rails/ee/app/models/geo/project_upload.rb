# frozen_string_literal: true

# Read-only model for the project_uploads upload partition table.
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
# The composite primary key (id, model_type) is overridden to just `id`
# since `id` is globally unique across all partitions (shared sequence).
# See: https://gitlab.com/gitlab-org/gitlab/-/issues/536647
module Geo
  class ProjectUpload < ::Upload
    include ::Geo::ReplicableModel
    include ::Geo::VerifiableModel
    extend ::Gitlab::Utils::Override

    self.table_name = 'project_uploads'
    self.primary_key = :id

    delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :project_upload_state)

    with_replicator Geo::ProjectUploadReplicator

    has_one :project_upload_state,
      autosave: false,
      inverse_of: :project_upload,
      class_name: 'Geo::ProjectUploadState'

    scope :project_id_in, ->(ids) { where(project_id: ids) }

    def verification_state_object
      project_upload_state
    end

    def project_upload_state
      super || build_project_upload_state
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
        :project_upload_id
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::ProjectUploadState
      end
    end
  end
end
