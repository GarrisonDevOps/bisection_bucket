# frozen_string_literal: true

module EE
  module Projects
    module DestroyService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        # Secrets manager cleanup is driven by the database now. The FK
        # on `project_secrets_managers.project_id` is `ON DELETE CASCADE`,
        # so destroying the project also deletes the SM row, which fires
        # the `enqueue_psm_deprovision_task_after_delete` trigger. The
        # trigger inserts a deprovision maintenance task carrying the
        # snapshot ids it reads off the SM's denormalized columns; the
        # cron worker picks it up and tears down OpenBao asynchronously.
        # See gitlab-org/gitlab#600290.
        super.tap do
          mirror_cleanup(project) if project&.destroyed?
        end
      end

      private

      override :destroy_project_related_records
      def destroy_project_related_records(project)
        destroy_compliance_requirement_statuses!
        destroy_ai_catalog_items!

        with_scheduling_epic_cache_update do
          super && log_destroy_events
        end
      end

      # rubocop:disable Scalability/BulkPerformWithContext
      def with_scheduling_epic_cache_update
        ids = project.epic_ids_referenced_by_issues

        yield

        ::Epics::UpdateCachedMetadataWorker.bulk_perform_in(
          1.minute,
          ids.each_slice(::Epics::UpdateCachedMetadataWorker::BATCH_SIZE).map { |ids| [ids] }
        )
      end
      # rubocop:enable Scalability/BulkPerformWithContext

      def log_destroy_events
        log_geo_event(project)
        log_audit_event(project)
      end

      override :execute_hooks
      def execute_hooks(project)
        super
        return unless project.has_active_hooks?(:project_hooks)

        hook_data = ::Gitlab::HookData::ProjectBuilder.new(project).build(:destroy)
        project.execute_hooks(hook_data, :project_hooks)
      end

      def mirror_cleanup(project)
        return unless project.mirror?

        ::Gitlab::Mirror.decrement_capacity(project.id)
      end

      def log_geo_event(project)
        project.geo_handle_after_destroy
        project.wiki_repository.geo_handle_after_destroy if project.wiki_repository
        project.design_management_repository.geo_handle_after_destroy if project.design_management_repository
      end

      def log_audit_event(project)
        audit_scope = if project.parent.instance_of?(::Namespaces::UserNamespace)
                        ::Gitlab::Audit::InstanceScope.new
                      else
                        project.parent
                      end

        audit_context = {
          name: 'project_destroyed',
          author: current_user,
          scope: audit_scope,
          target: project,
          message: "Project '#{project.full_path}' was deleted",
          target_details: project.full_path,
          additional_details: {
            remove: 'project',
            project_id: project.id,
            project_name: project.name,
            project_full_path: project.full_path,
            namespace_id: project.namespace_id,
            namespace_name: project.namespace&.name,
            namespace_path: project.namespace&.path
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def destroy_compliance_requirement_statuses!
        ::ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus
          .delete_all_project_statuses(project.id)
      end

      def destroy_ai_catalog_items!
        project_owned_items = ::Ai::Catalog::Item.for_project(project)

        # Hard delete items that have no remaining consumers
        project_owned_items.without_consumers.delete_all

        # Soft delete all items owned by the project
        project_owned_items.update_all(
          project_id: nil,
          deleted_at: Time.zone.now
        )
      end
    end
  end
end
