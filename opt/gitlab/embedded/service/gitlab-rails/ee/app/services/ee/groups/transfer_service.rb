# frozen_string_literal: true

module EE
  module Groups
    module TransferService
      extend ::Gitlab::Utils::Override

      PROJECT_QUERY_BATCH_SIZE = 1000
      GROUP_QUERY_BATCH_SIZE = 1000

      override :ensure_allowed_transfer
      def ensure_allowed_transfer
        super

        raise_transfer_error(:saml_provider_or_scim_token_present) if saml_provider_or_scim_token_present?
        raise_transfer_error(:user_exceeded_top_level_group_limit) if user_exceeded_top_level_group_limit?
      end

      override :localized_error_messages
      def localized_error_messages
        {
          saml_provider_or_scim_token_present:
            s_('TransferGroup|SAML Provider or SCIM Token is configured for this group.'),
          user_exceeded_top_level_group_limit:
            s_('TransferGroup|You have reached the limit of three top-level groups. To transfer this group ' \
              'to the top-level, reduce the number of top-level groups you have, or upgrade to a paid tier.')
        }
          .merge(super).freeze
      end

      override :proceed_to_transfer
      def proceed_to_transfer
        # Transfer is different from destroy: the base service doesn't
        # walk into child groups or projects. It just moves THIS group
        # to a new parent, but doing so quietly changes the root
        # ancestor (and therefore the OpenBao paths) for every
        # descendant too. So we need to handle each one ourselves:
        # this group, every subgroup beneath it, and every project in
        # the tree.
        #
        # Each SM row carries the OLD `organization_id` and OLD
        # `root_namespace_id` in its denormalized columns (set on SM
        # create and never updated). Bulk-destroying the SM rows fires
        # the AFTER DELETE trigger per row, which inserts a deprovision
        # maintenance task with those OLD ids. The cron worker picks
        # the tasks up and tears down OpenBao at the OLD paths. See
        # gitlab-org/gitlab#600290.
        #
        # We do NOT block transfer based on secrets manager state. If
        # an SM in the hierarchy is mid-provisioning, we just let the
        # transfer proceed. The orphan reaper
        # (gitlab-org/gitlab#600120) sweeps anything left in a
        # transient state.
        old_full_path = group.full_path

        super.tap do
          log_group_transfer_audit_event(old_full_path)
          bulk_initiate_secrets_manager_deprovisions
        end
      end

      private

      override :update_group_attributes
      def update_group_attributes
        super

        top_level_group_limit.record_creation!(group) unless new_parent_group
      end

      override :add_owner_on_transferred_group
      def add_owner_on_transferred_group
        return super unless ::Namespaces::FreeUserCap::Enforcement.new(group).enforce_cap?

        ::Members::Groups::CreatorService.add_member(group, current_user, :owner, ignore_user_limits: true)
      end

      def saml_provider_or_scim_token_present?
        group.saml_provider.present? || group.scim_auth_access_token.present?
      end

      # Bulk-destroys SMs across the transferred subtree. The AFTER
      # DELETE trigger handles task creation per row; no Sidekiq
      # enqueue happens here because cron picks the trigger-created
      # tasks up via the `:unprocessed` scope within ~1 minute.
      def bulk_initiate_secrets_manager_deprovisions
        group.self_and_descendants.each_batch(of: GROUP_QUERY_BATCH_SIZE) do |groups|
          ::SecretsManagement::GroupSecretsManagers::InitiateDeprovisionService.bulk_initiate_for_groups(groups)
        end

        group.all_projects.each_batch(of: PROJECT_QUERY_BATCH_SIZE) do |projects|
          ::SecretsManagement::ProjectSecretsManagers::InitiateDeprovisionService.bulk_initiate_for_projects(projects)
        end
      end

      def user_exceeded_top_level_group_limit?
        return false if new_parent_group
        return top_level_group_limit.exceeded? if ::Namespaces::TopLevelGroupLimit.enabled?
        return false if current_user.exempt_from_top_level_group_limit?

        if group.namespace_details.creator.present?
          group.namespace_details.creator.enforce_top_level_group_limit?
        else
          current_user.enforce_top_level_group_limit?
        end
      end

      def top_level_group_limit
        @top_level_group_limit ||= ::Namespaces::TopLevelGroupLimit.new(current_user)
      end

      def log_group_transfer_audit_event(old_full_path)
        return if old_full_path == group.full_path

        audit_context = {
          name: 'group_path_updated',
          author: current_user,
          scope: group,
          target: group,
          message: "Changed path from #{old_full_path} to #{group.full_path}",
          target_details: group.full_path,
          additional_details: {
            change: 'path',
            from: old_full_path,
            to: group.full_path,
            target_details: group.full_path
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      override :post_update_hooks
      def post_update_hooks(updated_project_ids, old_root_ancestor_id)
        super

        # When a group is moved to a new group, there is no way to know whether the group was using Elasticsearch
        # before the transfer. If Elasticsearch limit indexing is enabled, the group has the ES cache invalidated.
        elasticsearch_limit_indexing_enabled = ::Gitlab::CurrentSettings.elasticsearch_limit_indexing?
        group.invalidate_elasticsearch_indexes_cache! if elasticsearch_limit_indexing_enabled
        zoekt_enabled = ::Search::Zoekt.licensed_and_indexing_enabled?

        # If zoekt is not enabled then we must not do db query as we will skip all zoekt related steps
        old_namespace_had_zoekt_enabled = ::Namespace.find_by_id(old_root_ancestor_id)&.use_zoekt? if zoekt_enabled
        delete_from_old_zoekt_index = old_namespace_had_zoekt_enabled && old_root_ancestor_id != group.root_ancestor.id
        index_in_new_root = group.root_ancestor.use_zoekt? if zoekt_enabled

        group.all_projects.each_batch(of: PROJECT_QUERY_BATCH_SIZE) do |projects|
          # The Zoekt job context reads each project's organization, namespace and full path.
          # rubocop:disable CodeReuse/ActiveRecord -- Avoids an N+1 per batch from each_batch
          projects = projects.preload(:route, :organization, :namespace) if zoekt_enabled
          # rubocop:enable CodeReuse/ActiveRecord

          projects.each do |project|
            if zoekt_enabled
              process_zoekt_project(old_root_ancestor_id, delete_from_old_zoekt_index, index_in_new_root, project)
            end

            process_elasticsearch_project(project, elasticsearch_limit_indexing_enabled)
            delete_project_associations_with_old_routing(project)

            remove_project_compliance_frameworks(project) if should_remove_compliance_frameworks?(old_root_ancestor_id)
          end
        end

        process_group_associations(old_root_ancestor_id, group)

        sync_security_policies(group, current_user)
        sync_inherited_service_accounts(old_root_ancestor_id)

        remove_orbit_namespace_records
      end

      def sync_inherited_service_accounts(old_root_ancestor_id)
        ::Ai::Catalog::ItemConsumers::SyncTransferredProjectsService.new(
          group.all_projects,
          old_root_namespace_id: old_root_ancestor_id,
          new_root_namespace_id: group.root_ancestor.id,
          current_user: current_user
        ).execute
      end

      def sync_security_policies(group, current_user)
        return unless ::Security::PolicyAvailability.available?(group, :security_orchestration_policies)

        ::Security::Policies::GroupTransferWorker.perform_async(group.id, current_user.id)
      end

      def remove_orbit_namespace_records
        return if group.root?

        group.knowledge_graph_enabled_namespace&.destroy
        group.orbit_namespace_enrollment&.destroy
      end

      def update_project_settings(updated_project_ids)
        ::ProjectSetting.for_projects(updated_project_ids).update_all(legacy_open_source_license_available: false)
      end

      def process_zoekt_project(old_root_ancestor_id, delete_from_old_zoekt_index, index_in_new_root, project)
        return unless delete_from_old_zoekt_index || index_in_new_root

        ::Search::Zoekt.with_project_context(project) do
          if delete_from_old_zoekt_index
            ::Search::Zoekt.delete_async(project.id, root_namespace_id: old_root_ancestor_id)
          end

          ::Search::Zoekt.index_async(project.id) if index_in_new_root
        end
      end

      # Schedules deletion of stale ES documents for all project-scoped index types after a group
      # transfer. Uses the 'all' task so that DeleteWorker fans out to each PROJECT_TASK, respecting
      # any per-task migration guards (e.g. create_vulnerability_reads_index).
      def delete_project_associations_with_old_routing(project)
        return unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        ::Search::Elastic::DeleteWorker.perform_async(
          'task' => 'all',
          'traversal_id' => project.namespace.elastic_namespace_ancestry, # new traversal_id after transfer
          'project_id' => project.id
        )
      end

      def process_elasticsearch_project(project, elasticsearch_limit_indexing_enabled)
        # When a group is moved to a new group, there is no way to know whether the group was using Elasticsearch
        # before the transfer. If Elasticsearch limit indexing is enabled, each project has the ES cache invalidated.
        project.invalidate_elasticsearch_indexes_cache! if elasticsearch_limit_indexing_enabled
        # Reindex all projects and associated data to make sure the namespace_ancestry field gets
        # updated in each document.
        ::Elastic::ProcessInitialBookkeepingService.backfill_projects!(project) if project.maintaining_elasticsearch?
      end

      def process_group_associations(old_root_ancestor_id, group)
        return unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        root_ancestor_changed = old_root_ancestor_id != group.root_ancestor.id

        sync_transferred_groups(group, old_root_ancestor_id, root_ancestor_changed)

        if group.use_elasticsearch?
          process_wikis(group)
          process_epics_and_milestones(group)
        end

        return unless root_ancestor_changed

        ::Search::ElasticGroupAssociationDeletionWorker.perform_async(
          group.id,
          old_root_ancestor_id,
          { 'include_descendants' => true }
        )
      end

      def process_epics_and_milestones(group)
        epics_available = group.licensed_feature_available?(:epics)

        group.self_and_descendants.each_batch do |group_batch|
          if epics_available
            ::Epic.in_selected_groups(group_batch).each_batch do |epics|
              ::Elastic::ProcessInitialBookkeepingService.track!(*epics)
            end
          end

          milestones = ::Milestone.of_groups(group_batch.pluck_primary_key).with_group.order_by_group_and_id
          ::Gitlab::Pagination::Keyset::Iterator.new(scope: milestones).each_batch do |batch|
            ::Elastic::ProcessInitialBookkeepingService.track!(*batch)
          end
        end
      end

      def process_wikis(group)
        group.self_and_descendants.find_each.with_index do |grp, idx|
          interval = idx % ElasticWikiIndexerWorker::MAX_JOBS_PER_HOUR
          ElasticWikiIndexerWorker.perform_in(interval, grp.id, grp.class.name, { 'force' => true })
        end
      end

      override :transfer_status_data
      def transfer_status_data(old_root_ancestor_id)
        return unless old_root_ancestor_id

        old_root_ancestor = ::Group.find_by_id(old_root_ancestor_id)
        new_root_namespace = new_parent_group&.root_ancestor || group

        if group_is_already_root?
          # When the group is already root, we need first to copy the lifecycles from the old root namespace
          # to the new root namespace, and then adjust the statuses to the new root namespace
          ::WorkItems::Widgets::Statuses::TransferLifecycleService.new(
            old_root_namespace: old_root_ancestor,
            new_root_namespace: new_root_namespace
          ).execute
        end

        group.all_projects.each_batch(of: PROJECT_QUERY_BATCH_SIZE) do |projects|
          # rubocop:disable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord -- There is a limit from each_batch, for better performance
          project_namespace_ids = projects.pluck(:project_namespace_id)
          transfer_statuses(old_root_ancestor, new_root_namespace, project_namespace_ids)
          # rubocop:enable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord
        end
      end

      override :remove_paid_features_for_projects
      def remove_paid_features_for_projects(old_root_ancestor_id)
        return if old_root_ancestor_id == group.root_ancestor.id

        group.all_projects.each_batch(of: PROJECT_QUERY_BATCH_SIZE) do |projects|
          projects.each do |project|
            ::EE::Projects::RemovePaidFeaturesService.new(project).execute(new_parent_group)
          end
        end
      end

      def transfer_statuses(old_root_ancestor, new_root_namespace, project_namespace_ids)
        ::WorkItems::Widgets::Statuses::TransferService.new(
          old_root_namespace: old_root_ancestor,
          # Reset to include lifecycles created in previous iterations
          new_root_namespace: new_root_namespace.reset,
          project_namespace_ids: project_namespace_ids
        ).execute
      end

      def should_remove_compliance_frameworks?(old_root_ancestor_id)
        return false unless group.licensed_feature_available?(:custom_compliance_frameworks)

        old_root_ancestor_id && old_root_ancestor_id != group.root_ancestor.id
      end

      def remove_project_compliance_frameworks(project)
        project.compliance_framework_settings.each do |framework_setting|
          framework_id = framework_setting.framework_id

          framework_setting.delete
          ComplianceManagement::ComplianceFrameworkChangesAuditor.new(current_user, framework_setting,
            project).execute

          ComplianceManagement::ComplianceFramework::ProjectComplianceStatusesRemovalWorker.perform_async(
            project.id, framework_id, { "skip_framework_check" => true }
          )
        end
      end

      def sync_transferred_groups(group, old_root_ancestor_id, root_ancestor_changed)
        reindex = group.use_elasticsearch?
        return unless root_ancestor_changed || reindex

        group.self_and_descendants.each_batch(of: GROUP_QUERY_BATCH_SIZE) do |batch|
          groups = batch.to_a

          if root_ancestor_changed
            ::Search::Elastic::DeleteWorker.perform_async(
              'task' => 'delete_groups',
              'group_ids' => groups.map(&:id),
              'ancestor_id' => old_root_ancestor_id
            )
          end

          ::Elastic::ProcessInitialBookkeepingService.track!(*groups) if reindex
        end
      end
    end
  end
end
