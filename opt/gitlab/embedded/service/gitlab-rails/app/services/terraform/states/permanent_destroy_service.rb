# frozen_string_literal: true

module Terraform
  module States
    class PermanentDestroyService
      def initialize(state, current_user:)
        @state = state
        @current_user = current_user
      end

      def execute
        return unauthorized_response unless can_destroy_state?
        return protected_response if protected_state?
        return not_deleted_response unless state.deleted_at?

        Terraform::States::DestroyWorker.perform_async(state.id, { 'permanent' => true, 'user_id' => current_user.id })

        ServiceResponse.success
      end

      private

      attr_reader :state, :current_user

      def can_destroy_state?
        Ability.allowed?(current_user, :delete_terraform_state, state.project)
      end

      def protected_state?
        Terraform::StateProtectionRules::CheckRuleExistenceService.new(
          project: state.project,
          current_user: current_user,
          params: { state_name: state.name }
        ).execute.payload[:protection_rule_exists?]
      end

      def unauthorized_response
        error_response(s_('Terraform|You have insufficient permissions to permanently delete this state'))
      end

      def protected_response
        error_response(s_('Terraform|Write access to this Terraform state is restricted by a protection rule'))
      end

      def not_deleted_response
        error_response(s_('Terraform|State must be marked for deletion before it can be permanently deleted'))
      end

      def error_response(message)
        ServiceResponse.error(message: message)
      end
    end
  end
end
