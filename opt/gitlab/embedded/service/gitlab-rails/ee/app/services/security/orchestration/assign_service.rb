# frozen_string_literal: true

module Security
  module Orchestration
    class AssignService < ::BaseContainerService
      def execute
        validate_access!

        return error(_("Security policy project is already assigned.")) if policy_project_assigned?

        if csp_group_with_existing_policy?
          return error(_("You cannot modify security policy project for group designated as CSP."))
        end

        if policy_project_inherited?
          return error(_("You don't need to link the security policy projects from the group. " \
                         "All policies in the security policy projects are inherited already."))
        end

        return error(_('Policy project doesn\'t exist')) if policy_project_out_of_organization?

        if create_or_update_security_policy_configuration
          unassign_redundant_configurations if group_container?

          success
        end
      rescue ActiveRecord::RecordNotFound => _
        error(_('Policy project doesn\'t exist'))
      rescue ActiveRecord::RecordInvalid => _
        error(_('Couldn\'t assign policy to project or group'))
      end

      private

      def validate_access!
        return if Ability.allowed?(current_user, :update_security_orchestration_policy_project, container)

        raise Gitlab::Access::AccessDeniedError
      end

      def create_or_update_security_policy_configuration
        return unassign_policy_project if unassigning? && has_existing_policy?

        return reassign_policy_project(policy_project) if has_existing_policy?

        assign_policy_project(policy_project)
      end

      def policy_project
        Project.find(policy_project_id)
      end
      strong_memoize_attr :policy_project

      # A policy project from another organization must never be linkable - checked separately
      # from create_or_update_security_policy_configuration so a rejection returns a
      # ServiceResponse.error instead of being read as success by the truthy check in #execute.
      def policy_project_out_of_organization?
        return false if unassigning?

        policy_project.organization_id != container.organization_id
      end

      def assign_policy_project(policy_project)
        create_result = container.create_security_orchestration_policy_configuration! do |p|
          p.security_policy_management_project_id = policy_project.id
        end

        if create_result
          create_security_policy_project_bot

          audit(policy_project, "Linked #{policy_project.name} as the security policy project")

          Security::SyncScanPoliciesWorker.perform_async(
            container.security_orchestration_policy_configuration.id,
            Security::SecurityOrchestrationPolicies::SyncReason.to_params(:configuration_assigned)
          )
        end

        create_result
      end

      def unassign_policy_project
        result = UnassignService.new(container: container, current_user: current_user).execute(delete_bot: false)

        result.success?
      end

      def reassign_policy_project(policy_project)
        configuration = container.security_orchestration_policy_configuration
        old_policy_project = configuration.security_policy_management_project

        update_result = configuration.update!(security_policy_management_project_id: policy_project.id)

        if update_result
          audit(
            policy_project,
            "Changed the linked security policy project from #{old_policy_project.name} to #{policy_project.name}"
          )

          Security::SyncScanPoliciesWorker.perform_async(
            configuration.id,
            Security::SecurityOrchestrationPolicies::SyncReason.to_params(:force_resync)
          )
        end

        update_result
      end

      def audit(policy_project, message)
        ::Gitlab::Audit::Auditor.audit(
          name: 'policy_project_updated',
          author: current_user,
          scope: container,
          target: policy_project,
          message: message
        )
      end

      def success
        ServiceResponse.success(payload: { policy_project: policy_project_id })
      end

      def error(message)
        ServiceResponse.error(payload: { policy_project: policy_project_id }, message: message)
      end

      def has_existing_policy?
        container.security_orchestration_policy_configuration.present?
      end

      def policy_project_id
        params[:policy_project_id]
      end

      def create_security_policy_project_bot
        if container.is_a?(Project)
          Security::OrchestrationConfigurationCreateBotWorker.perform_async(container.id, current_user.id)
        else
          Security::OrchestrationConfigurationCreateBotForNamespaceWorker.perform_async(container.id, current_user.id)
        end
      end

      def unassign_redundant_configurations
        ::Security::UnassignRedundantPolicyConfigurationsWorker
          .perform_async(container.id, policy_project_id, current_user.id)
      end

      def policy_project_assigned?
        attrs = if project_container?
                  { project_id: container.id, security_policy_management_project_id: policy_project_id }
                else
                  { namespace_id: container.id, security_policy_management_project_id: policy_project_id }
                end

        # rubocop:disable CodeReuse/ActiveRecord -- Not suitable for a scope
        Security::OrchestrationPolicyConfiguration.exists?(attrs)
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def csp_group_with_existing_policy?
        container.designated_as_csp? && has_existing_policy?
      end

      def policy_project_inherited?
        all_effective_policy_project_ids.include?(policy_project_id)
      end

      def all_effective_policy_project_ids
        # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- plucking an Array
        # rubocop:disable CodeReuse/ActiveRecord -- plucking an Array
        container
          .all_security_orchestration_policy_configurations(include_invalid: true)
          .pluck(:security_policy_management_project_id)
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def unassigning?
        policy_project_id.blank?
      end
    end
  end
end
