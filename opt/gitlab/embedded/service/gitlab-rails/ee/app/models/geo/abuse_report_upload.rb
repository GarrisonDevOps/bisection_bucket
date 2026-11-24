# frozen_string_literal: true

# Read-only model for the abuse_report_uploads upload partition table.
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
  class AbuseReportUpload < ::Upload
    include ::Geo::ReplicableModel
    include ::Geo::VerifiableModel
    extend ::Gitlab::Utils::Override

    self.table_name = 'abuse_report_uploads'
    self.primary_key = :id

    delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :abuse_report_upload_state)

    with_replicator Geo::AbuseReportUploadReplicator

    has_one :abuse_report_upload_state,
      autosave: false,
      inverse_of: :abuse_report_upload,
      class_name: 'Geo::AbuseReportUploadState'

    scope :organization_id_in, ->(ids) { where(organization_id: ids) }

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
        :abuse_report_upload_id
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::AbuseReportUploadState
      end
    end

    def verification_state_object
      abuse_report_upload_state
    end

    def abuse_report_upload_state
      super || build_abuse_report_upload_state
    end
  end
end
