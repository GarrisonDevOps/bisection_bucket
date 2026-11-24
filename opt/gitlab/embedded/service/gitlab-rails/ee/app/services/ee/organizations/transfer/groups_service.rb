# frozen_string_literal: true

module EE
  module Organizations
    module Transfer
      module GroupsService
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize
        include ::Organizations::Transfer::GroupTransferAuditing

        override :execute
        def execute
          # When the root is already on the target, TopLevelGroupService moved it and logged
          # the transfer (activation), or this is a forced catch-up, so only log when this run
          # moves the root.
          source_organization_id = group.organization_id unless group.organization_id == new_organization&.id
          result = super

          log_group_transferred_audit_event(group, source_organization_id) if result.success? && source_organization_id

          result
        end

        override :perform_transfer
        def perform_transfer
          super

          transfer_subscriptions
          transfer_ai_catalog_items
          transfer_ai_token_daily_usages
          transfer_custom_dashboards
          transfer_security_export_uploads
          transfer_upcoming_reconciliations
          transfer_organization_cluster_agent_mappings
          unassign_csp_namespace
        end

        override :publish_post_transfer_side_effects
        def publish_post_transfer_side_effects
          super

          schedule_security_exports_transfer
          schedule_sbom_transfer
          schedule_cross_organization_policy_unassignment
        end

        private

        # The old organization's settings stay with it, but a group that left the organization
        # must not keep centrally managing that organization's security policies.
        # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
        def unassign_csp_namespace
          setting = ::Security::PolicySetting.find_by(organization: old_organization, csp_namespace: group)
          return unless setting

          # Unlock first to pass validation; before_save re-locks, so reset the lock after saving.
          setting.update!(csp_namespace_id: nil, csp_namespace_locked_until: nil)
          setting.update_column(:csp_namespace_locked_until, nil)
        end
        # rubocop:enable CodeReuse/ActiveRecord

        def schedule_cross_organization_policy_unassignment
          ::Security::UnassignCrossOrganizationPolicyConfigurationsWorker.perform_async(group.id)
        end

        def transfer_subscriptions
          update_organization_id_for(::GitlabSubscriptions::AddOnPurchase) { |relation| relation.by_namespace(group) }
          update_organization_id_for(::GitlabSubscriptions::SeatAssignment) { |relation| relation.by_namespace(group) }

          update_organization_id_for(::GitlabSubscriptions::UserAddOnAssignment) do |relation|
            relation.for_add_on_purchases(add_on_purchases_relation)
          end

          update_organization_id_for(::GitlabSubscriptions::UserAddOnAssignmentVersion) do |relation|
            relation.for_add_on_purchases(add_on_purchases_relation)
          end
        end

        def add_on_purchases_relation
          ::GitlabSubscriptions::AddOnPurchase.by_namespace(group)
        end
        strong_memoize_attr :add_on_purchases_relation

        # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
        # Child scopes filter on project_id via the item, so they stay valid after the parent moves.
        def transfer_ai_catalog_items
          items = ::Ai::Catalog::Item.where(project_id: projects)
          item_versions = ::Ai::Catalog::ItemVersion.where(ai_catalog_item_id: items.select(:id))

          update_organization_id_for(::Ai::Catalog::ItemVersionDependency) do |relation|
            relation.where(ai_catalog_item_version_id: item_versions.select(:id))
          end

          update_organization_id_for(::Ai::Catalog::ItemVersion) do |relation|
            relation.where(ai_catalog_item_id: items.select(:id))
          end

          update_organization_id_for(::Ai::Catalog::ItemStar) do |relation|
            relation.where(ai_catalog_item_id: items.select(:id))
          end

          update_organization_id_for(::Ai::Catalog::Item) do |relation|
            relation.where(project_id: projects)
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord

        # Rows outside a group's chain move in UsersService: those under a personal namespace
        # with its owner, the rest with their user.
        def transfer_ai_token_daily_usages
          ::Ai::TokenDailyUsage.transfer_organization(
            ::Ai::TokenDailyUsage.within(group.traversal_ids), from: old_organization.id, to: new_organization.id
          )
        end

        def transfer_custom_dashboards
          # Dashboards scoped to a namespace in the transferred group move with
          # it; organization-scoped dashboards (namespace_id: nil) stay with the
          # old organization. The dashboards subquery filters on namespace_id
          # only, so it stays valid after the parent update below.
          dashboards = ::Analytics::CustomDashboards::Dashboard.by_namespace(descendant_namespace_ids)

          update_organization_id_for(::Analytics::CustomDashboards::Dashboard) do |relation|
            relation.by_namespace(descendant_namespace_ids)
          end

          update_organization_id_for(::Analytics::CustomDashboards::SearchData) do |relation|
            relation.for_custom_dashboards(dashboards)
          end

          update_organization_id_for(::Analytics::CustomDashboards::DashboardVersion) do |relation|
            relation.for_custom_dashboards(dashboards)
          end
        end

        # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service

        # Phase 1: Synchronous transfer of upload tables (gitlab_main_org)
        # and their associated state tables (trigger-fire pattern).
        #
        # Upload partition tables use model_id to reference their parent
        # (Part or Export) on gitlab_sec. We load parent IDs into Ruby
        # to avoid cross-database subqueries.
        def transfer_security_export_uploads
          transfer_dep_part_uploads
          transfer_vuln_export_uploads
          transfer_vuln_part_uploads
        end

        def transfer_dep_part_uploads
          part_ids = dep_list_export_part_ids
          return if part_ids.empty?

          transfer_uploads_and_fire_trigger(
            ::Geo::DependencyListExportPartUpload,
            ::Geo::DependencyListExportPartUploadState,
            :dependency_list_export_part_upload_id,
            part_ids
          )
        end

        def transfer_vuln_export_uploads
          export_ids = vuln_export_ids
          return if export_ids.empty?

          transfer_uploads_and_fire_trigger(
            ::Geo::VulnerabilityExportUpload,
            ::Geo::VulnerabilityExportUploadState,
            :vulnerability_export_upload_id,
            export_ids
          )
        end

        def transfer_vuln_part_uploads
          part_ids = vuln_export_part_ids
          return if part_ids.empty?

          transfer_uploads_and_fire_trigger(
            ::Geo::VulnerabilityExportPartUpload,
            ::Geo::VulnerabilityExportPartUploadState,
            :vulnerability_export_part_upload_id,
            part_ids
          )
        end

        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by model_id_batch (at most batch_size parent IDs)
        def transfer_uploads_and_fire_trigger(upload_class, state_class, parent_fk, parent_model_ids)
          batch_size = ::Organizations::Transfer::Concerns::OrganizationUpdater::ORGANIZATION_ID_UPDATE_BATCH_SIZE

          parent_model_ids.each_slice(batch_size) do |model_id_batch|
            scoped = upload_class.where(model_id: model_id_batch, organization_id: old_organization.id)
            upload_ids = scoped.pluck(:id)
            next if upload_ids.empty?

            upload_class.where(id: upload_ids)
              .update_all(organization_id: new_organization.id)

            state_class
              .where(parent_fk => upload_ids)
              .where(organization_id: old_organization.id)
              .update_all(organization_id: nil)
          end
        end
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit

        # Load IDs from gitlab_sec into Ruby to avoid cross-database
        # subqueries between gitlab_main_org and gitlab_sec.
        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- cross-DB workaround, bounded by group hierarchy
        def descendant_group_ids
          group.self_and_descendant_ids.pluck(:id)
        end
        strong_memoize_attr :descendant_group_ids

        def descendant_project_ids
          ::Project.in_namespace(group.self_and_descendant_ids(skope: ::Namespace)).pluck(:id)
        end
        strong_memoize_attr :descendant_project_ids

        def dep_list_export_ids
          ::Dependencies::DependencyListExport
            .where(group_id: descendant_group_ids)
            .or(::Dependencies::DependencyListExport.where(project_id: descendant_project_ids))
            .pluck(:id)
        end
        strong_memoize_attr :dep_list_export_ids

        def dep_list_export_part_ids
          return [] if dep_list_export_ids.empty?

          ::Dependencies::DependencyListExport::Part
            .where(dependency_list_export_id: dep_list_export_ids)
            .pluck(:id)
        end
        strong_memoize_attr :dep_list_export_part_ids

        def vuln_export_ids
          ::Vulnerabilities::Export
            .where(group_id: descendant_group_ids)
            .or(::Vulnerabilities::Export.where(project_id: descendant_project_ids))
            .pluck(:id)
        end
        strong_memoize_attr :vuln_export_ids

        def vuln_export_part_ids
          return [] if vuln_export_ids.empty?

          ::Vulnerabilities::Export::Part
            .where(vulnerability_export_id: vuln_export_ids)
            .pluck(:id)
        end
        strong_memoize_attr :vuln_export_part_ids
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit

        # rubocop:enable CodeReuse/ActiveRecord

        def schedule_security_exports_transfer
          ::Organizations::Transfer::SecurityExportsWorker.perform_async(
            group.id, old_organization.id, new_organization.id
          )
        end

        def transfer_upcoming_reconciliations
          update_organization_id_for(::GitlabSubscriptions::UpcomingReconciliation) do |relation|
            relation.by_namespace_ids(descendant_namespace_ids)
          end
        end

        # ClusterAgentValidator requires a mapping's organization to match its agent's project.
        # rubocop:disable CodeReuse/ActiveRecord -- Query specific to this service
        def transfer_organization_cluster_agent_mappings
          agent_ids = ::Clusters::Agent.for_projects(projects).select(:id)

          update_organization_id_for(::RemoteDevelopment::OrganizationClusterAgentMapping) do |relation|
            relation.where(cluster_agent_id: agent_ids)
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord

        def schedule_sbom_transfer
          ::Organizations::Transfer::SbomWorker.perform_async(group.id, old_organization.id, new_organization.id)
        end

        def descendant_namespace_ids
          group.self_and_descendant_ids(skope: ::Namespace)
        end
        strong_memoize_attr :descendant_namespace_ids
      end
    end
  end
end
