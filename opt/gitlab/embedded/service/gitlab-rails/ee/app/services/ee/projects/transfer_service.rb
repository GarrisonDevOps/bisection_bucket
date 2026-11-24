# frozen_string_literal: true

module EE
  module Projects
    module TransferService
      extend ::Gitlab::Utils::Override

      private

      override :execute_system_hooks
      def execute_system_hooks
        super

        ::Projects::ProjectChangesAuditor.new(current_user, project).execute
      end

      override :transfer_missing_group_resources
      def transfer_missing_group_resources(group)
        super

        ::Epics::TransferService.new(current_user, group, project).execute

        transfer_status_data
      end

      override :post_update_hooks
      def post_update_hooks(project, old_group)
        super

        ::Elastic::ProjectTransferWorker.perform_async(project.id, old_namespace.id, new_namespace.id)
        ::Search::Zoekt::ProjectTransferWorker.perform_async(project.id, old_namespace.id)

        delete_compliance_framework_setting(old_group)
        update_compliance_standards_adherence
        delete_compliance_statuses
        sync_security_policies
        sync_inherited_service_accounts
        deprovision_secrets_manager(project.secrets_manager)
      end

      override :remove_paid_features
      def remove_paid_features
        ::EE::Projects::RemovePaidFeaturesService.new(project).execute(new_namespace)
      end

      def sync_inherited_service_accounts
        ::Ai::Catalog::ItemConsumers::SyncTransferredProjectsService.new(
          ::Project.id_in(project.id),
          old_root_namespace_id: old_namespace.root_ancestor.id,
          new_root_namespace_id: project.root_ancestor.id,
          current_user: current_user
        ).execute
      end

      def sync_security_policies
        return unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)

        ::Security::Policies::ProjectTransferWorker.perform_async(
          project.id, current_user.id, old_namespace.id, new_namespace.id
        )
      end

      def delete_compliance_framework_setting(old_group)
        return if old_group&.root_ancestor == project.group&.root_ancestor

        deleted_framework_settings = project.compliance_framework_settings.each(&:delete)

        deleted_framework_settings.each do |framework_setting|
          ComplianceManagement::ComplianceFrameworkChangesAuditor.new(current_user, framework_setting, project).execute
        end
      end

      def update_compliance_standards_adherence
        project.compliance_standards_adherence.update_all(namespace_id: new_namespace.id)
      end

      def delete_compliance_statuses
        project.compliance_framework_settings.each do |framework_setting|
          enqueue_project_compliance_status_removal(framework_setting.framework_id)
        end
      end

      def enqueue_project_compliance_status_removal(framework_id)
        ComplianceManagement::ComplianceFramework::ProjectComplianceStatusesRemovalWorker.perform_async(
          project.id, framework_id, { "skip_framework_check" => true }
        )
      end

      def transfer_status_data
        ::WorkItems::Widgets::Statuses::TransferService.new(
          old_root_namespace: old_namespace.root_ancestor,
          new_root_namespace: new_namespace.root_ancestor,
          project_namespace_ids: [project.project_namespace_id]
        ).execute
      end

      # When this hook runs the project has already been transferred,
      # but the SM row is still anchored to the OLD context (it carries
      # the OLD `organization_id` / `root_namespace_id` in its
      # denormalized columns, set on create and never updated). The
      # service destroys the SM, which fires the AFTER DELETE trigger
      # and inserts a deprovision maintenance task with those OLD
      # snapshot ids; the cron worker tears down the OLD OpenBao path.
      # See gitlab-org/gitlab#600290.
      #
      # `enqueue_worker: false` because this runs inside the transfer
      # transaction. `perform_async` here could fire before commit; the
      # cron picks the task up within ~1 minute via the `:unprocessed`
      # scope (`last_processed_at IS NULL` on trigger-created tasks).
      def deprovision_secrets_manager(secrets_manager)
        return unless secrets_manager

        ::SecretsManagement::ProjectSecretsManagers::InitiateDeprovisionService
          .new(secrets_manager, current_user, project_id: secrets_manager.project_id)
          .execute(enqueue_worker: false)
      end
    end
  end
end
