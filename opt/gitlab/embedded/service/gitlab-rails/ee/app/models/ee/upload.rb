# frozen_string_literal: true

module EE
  # Upload EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `Upload` model
  module Upload
    include ::Gitlab::Utils::StrongMemoize
    extend ActiveSupport::Concern

    # Geo partition model class names don't follow `model_type`, so the mapping is explicit.
    # Strings avoid autoload cycles: the Geo classes inherit from ::Upload.
    PARTITION_MODEL_CLASS_NAMES = {
      'AbuseReport' => 'Geo::AbuseReportUpload',
      'Achievements::Achievement' => 'Geo::AchievementUpload',
      'AlertManagement::MetricImage' => 'Geo::AlertManagementMetricImageUpload',
      'Appearance' => 'Geo::AppearanceUpload',
      'BulkImports::ExportUpload' => 'Geo::BulkImportExportUploadUpload',
      'Dependencies::DependencyListExport' => 'Geo::DependencyListExportUpload',
      'Dependencies::DependencyListExport::Part' => 'Geo::DependencyListExportPartUpload',
      'DesignManagement::Action' => 'Geo::DesignManagementActionUpload',
      'ImportExportUpload' => 'Geo::ImportExportUploadUpload',
      'IssuableMetricImage' => 'Geo::IssuableMetricImageUpload',
      'Namespace' => 'Geo::GroupUpload',
      'Organizations::OrganizationDetail' => 'Geo::OrganizationDetailUpload',
      'Project' => 'Geo::ProjectUpload',
      'Projects::ImportExport::RelationExportUpload' => 'Geo::ProjectImportExportRelationExportUploadUpload',
      'Projects::Topic' => 'Geo::ProjectTopicUpload',
      'Snippet' => 'Geo::PersonalSnippetUpload',
      'User' => 'Geo::UserUpload',
      'UserPermissionExportUpload' => 'Geo::UserPermissionExportUploadUpload',
      'Vulnerabilities::ArchiveExport' => 'Geo::VulnerabilityArchiveExportUpload',
      'Vulnerabilities::Export' => 'Geo::VulnerabilityExportUpload',
      'Vulnerabilities::Export::Part' => 'Geo::VulnerabilityExportPartUpload',
      'Vulnerabilities::Remediation' => 'Geo::VulnerabilityRemediationUpload'
    }.freeze

    prepended do
      include ::Gitlab::SQL::Pattern
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel
      extend ::Gitlab::Utils::Override

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :upload_state)

      with_replicator ::Geo::UploadReplicator

      scope :for_model, ->(model) { where(model_id: model.id, model_type: model.class.name) }
      # SPIKE (gitlab-org/gitlab#602803): used by the Geo cleanup tools to find uploads whose
      # verification failure matches a known-error pattern. Mirrors the registry-side
      # Geo::ReplicableRegistry.with_sync_failure_matching scope. Matches free text, so it is
      # not index-backed; fine for an on-demand diagnostic, not for a frequent cron.
      scope :with_verification_failure_matching, ->(pattern) {
        verification_failed.where(verification_arel_table[:verification_failure].matches("%#{sanitize_sql_like(pattern)}%"))
      }
      scope :by_checksum, ->(value) { where(checksum: value) }
      scope :for_uploader_and_path, ->(uploader_class, path) { for_uploader(uploader_class).where(path: path) }

      has_one :upload_state,
        autosave: false,
        inverse_of: :upload,
        class_name: '::Geo::UploadState'

      around_save :ignore_save_verification_details_in_transaction, prepend: true
      after_save :save_partition_verification_details
      after_create_commit :geo_create_partition_upload_event!
      after_destroy :geo_destroy_partition_upload_event!
    end

    def ignore_save_verification_details_in_transaction(&blk)
      ::Gitlab::Database::QueryAnalyzers::PreventCrossDatabaseModification.temporary_ignore_tables_in_transaction(
        %w[upload_states], url: "https://gitlab.com/gitlab-org/gitlab/-/issues/398199", &blk)
    end

    # Write verification state to the partition-specific state table
    # (e.g. abuse_report_upload_states) in addition to upload_states.
    #
    # Upload partition tables are tracked separately by Geo for
    # replication and verification so that verification state rows
    # can be migrated per-organization between GitLab instances.
    #
    # The partition model is resolved via PARTITION_MODEL_CLASS_NAMES:
    #   model_type "AbuseReport" -> Geo::AbuseReportUpload
    #
    # This is a no-op for model types without a partition replicator.
    # See: https://gitlab.com/groups/gitlab-org/-/work_items/20933
    def save_partition_verification_details
      return unless partition_record

      state_table = partition_record.class.verification_state_table_class.table_name
      ::Gitlab::Database::QueryAnalyzers::PreventCrossDatabaseModification.temporary_ignore_tables_in_transaction(
        [state_table], url: "https://gitlab.com/groups/gitlab-org/-/work_items/20933") do
        partition_record.save_verification_details
      end
    end

    # Publishes a Geo creation event via the partition replicator when
    # geo_upload_replication is disabled but the partition FF is enabled.
    #
    # This is needed because partition models (e.g. Geo::UserUpload) are
    # read-only - records are never created via them directly, so their
    # after_create_commit never fires. When switching away from the legacy
    # UploadReplicator, this hook ensures creation events still flow to the
    # appropriate partition replicator on the secondary.
    #
    # See: https://gitlab.com/gitlab-org/gitlab/-/work_items/594291
    def geo_create_partition_upload_event!
      return unless partition_model_replication_enabled?
      return unless partition_record

      partition_record.replicator.geo_handle_after_create
    rescue StandardError => err
      log_error('Geo partition upload replicator after_create_commit failed', err)
    end

    # Publishes a Geo deletion event via the partition replicator.
    #
    # The partition table row is already gone by the time after_destroy fires,
    # so we instantiate the replicator with self (the Upload record in memory)
    # rather than doing a DB lookup. Partition models inherit from Upload so
    # self is type-compatible for retrieving id and blob_path.
    #
    # See: https://gitlab.com/gitlab-org/gitlab/-/work_items/594291
    def geo_destroy_partition_upload_event!
      return unless partition_model_replication_enabled?

      partition_model_class.replicator_class.new(model_record: self).geo_handle_after_destroy
    rescue StandardError => err
      log_error('Geo partition upload replicator after_destroy failed', err)
    end

    # Returns the corresponding record from the partition table
    # (e.g. user_uploads, abuse_report_uploads).
    #
    # Memoized so that save_partition_verification_details and
    # geo_create_partition_upload_event! share a single DB lookup on create.
    #
    # Returns nil for model types without a partition replicator.
    def partition_record
      partition_model_class&.find_by(id: id)
    end
    strong_memoize_attr :partition_record

    def partition_model_class
      PARTITION_MODEL_CLASS_NAMES[model_type]&.constantize
    end
    strong_memoize_attr :partition_model_class

    def partition_model_replication_enabled?
      # When the parent model replication `geo_upload_replication` is enabled,
      # we do not replicate based on the partitioned model
      return false if self.class.replicator_class.replication_enabled?

      partition_model_class.present? && partition_model_class.replicator_class.replication_enabled?
    end

    def verification_state_object
      upload_state
    end

    def upload_state
      super || build_upload_state
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of uploads based on the query given in `query`.
      #
      # @param [String] query term that will search over upload :checksum attribute
      #
      # @return [ActiveRecord::Relation<Upload>] a collection of uploads
      def search(query)
        return all if query.empty?

        by_checksum(query)
      end

      # @return [ActiveRecord::Relation<Upload>] scope observing selective sync
      #          settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables    = params.fetch(:replicables, all)
        primary_key_in = params[:primary_key_in].presence
        replicables    = replicables.primary_key_in(primary_key_in) if primary_key_in

        return replicables unless node.selective_sync?

        if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
          uploads_for_selected_namespaces(node, replicables)
        elsif node.selective_sync_by_organizations?
          uploads_for_selected_organizations(node, replicables)
        else
          raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
        end
      end

      def uploads_for_selected_namespaces(node, replicables)
        namespace_ids = node.namespaces_for_group_owned_replicables.select(:id)
        project_ids = ::Project.selective_sync_scope(node).select(:id)

        group_attachments(replicables, namespace_ids)
          .or(project_attachments(replicables, project_ids))
          .or(other_attachments(replicables))
      end

      def uploads_for_selected_organizations(node, replicables)
        organization_ids = node.organizations.pluck_primary_key
        return none if organization_ids.empty?

        user_ids = ::Organizations::OrganizationUser.in_organization(organization_ids).select(:user_id)
        namespace_ids = node.namespaces_for_group_owned_replicables.select(:id)
        project_ids = ::Project.selective_sync_scope(node).select(:id)

        replicables
            .where(organization_id: organization_ids)
            .or(replicables.where(namespace_id: namespace_ids))
            .or(replicables.where(project_id: project_ids))
            .or(replicables.where(uploaded_by_user_id: user_ids))
      end

      # @return [ActiveRecord::Relation<Upload>] scope of Namespace-associated uploads observing selective sync settings of the given node
      def group_attachments(replicables, namespace_ids)
        replicables.where(model_type: 'Namespace', model_id: namespace_ids)
      end

      # @return [ActiveRecord::Relation<Upload>] scope of Project-associated uploads observing selective sync settings of the given node
      def project_attachments(replicables, project_ids)
        replicables.where(model_type: 'Project', model_id: project_ids)
      end

      # @return [ActiveRecord::Relation<Upload>] scope of uploads which are not associated with Namespace or Project
      def other_attachments(replicables)
        replicables.where.not(model_type: %w[Namespace Project])
      end

      override :verification_state_table_class
      def verification_state_table_class
        ::Geo::UploadState
      end
    end
  end
end
