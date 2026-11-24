# frozen_string_literal: true

module Security
  # Policy projects can only be linked within one organization, so links crossing a group's
  # boundary become invalid once the group moves to another organization.
  class UnassignCrossOrganizationPolicyConfigurationsWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    deduplicate :until_executed
    idempotent!

    def perform(group_id)
      group = Group.find_by_id(group_id)
      return unless group

      configuration_ids = Security::OrchestrationPolicyConfiguration.ids_linked_across_hierarchy(group.id)
      unassigned_count = 0

      Security::OrchestrationPolicyConfiguration.id_in(configuration_ids).find_each do |configuration|
        container = configuration.source
        # Links made after the transfer stay within one organization and are valid.
        next if container.organization_id == configuration.security_policy_management_project.organization_id

        response = Security::Orchestration::UnassignService
          .new(container: container, current_user: admin_bot_for_organization_id(container.organization_id))
          .execute(delete_bot: true, skip_csp: false)

        unassigned_count += 1 if response.success?
      end

      log_extra_metadata_on_done(:unassigned_configurations_count, unassigned_count)
    end

    private

    def admin_bot_for_organization_id(organization_id)
      @admin_bots ||= {}
      @admin_bots[organization_id] ||= Users::Internal.in_organization(organization_id).admin_bot
    end
  end
end
