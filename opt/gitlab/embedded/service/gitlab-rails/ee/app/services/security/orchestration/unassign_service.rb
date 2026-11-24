# frozen_string_literal: true

module Security
  module Orchestration
    class UnassignService < ::BaseContainerService
      include Gitlab::Utils::StrongMemoize

      def execute(delete_bot: true, skip_csp: true)
        return error(_('Policy project doesn\'t exist')) unless security_orchestration_policy_configuration

        if container.designated_as_csp? && skip_csp
          return error(_("You cannot unassign security policy project for group designated as CSP."))
        end

        old_policy_project = security_orchestration_policy_configuration.security_policy_management_project

        soft_delete_policies(security_orchestration_policy_configuration)

        remove_bot if delete_bot

        if should_delete_configuration?(delete_bot)
          delete_configuration(security_orchestration_policy_configuration, old_policy_project)
        end

        success
      end

      private

      delegate :security_orchestration_policy_configuration, to: :container

      def delete_configuration(configuration, old_policy_project)
        Security::DeleteOrchestrationConfigurationWorker.perform_async(
          configuration.id, current_user.id, old_policy_project.id)
      end

      def success
        ServiceResponse.success
      end

      def error(message)
        ServiceResponse.error(message: message)
      end

      def remove_bot
        if project?
          Security::OrchestrationConfigurationRemoveBotWorker.perform_async(container.id, current_user.id)
        else
          Security::OrchestrationConfigurationRemoveBotForNamespaceWorker.perform_async(container.id, current_user.id)
        end
      end

      def project?
        container.is_a?(Project)
      end
      strong_memoize_attr :project?

      def should_delete_configuration?(delete_bot)
        project? || (container.is_a?(Namespace) && !delete_bot)
      end

      def soft_delete_policies(configuration)
        configuration.soft_delete_all_policies
      end
    end
  end
end
