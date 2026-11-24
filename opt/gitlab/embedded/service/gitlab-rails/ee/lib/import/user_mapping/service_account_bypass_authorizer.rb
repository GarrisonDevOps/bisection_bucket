# frozen_string_literal: true

module Import
  module UserMapping
    class ServiceAccountBypassAuthorizer
      def initialize(group, assignee_user, reassigned_by_user)
        @group = group.root_ancestor
        @assignee_user = assignee_user
        @reassigned_by_user = reassigned_by_user
      end

      def allowed?
        return false unless Ability.allowed?(reassigned_by_user, :admin_namespace, group)
        return false unless assignee_user&.service_account?
        return service_account_provisioned_by_group? if group_service_account?

        admin_bypass_allowed?
      end

      private

      attr_reader :group, :assignee_user, :reassigned_by_user

      def group_service_account?
        assignee_user.provisioned_by_group_id.present?
      end

      def service_account_provisioned_by_group?
        assignee_user.provisioned_by_group_id == group.id
      end

      def admin_bypass_allowed?
        AdminBypassAuthorizer.new(reassigned_by_user).allowed?
      end
    end
  end
end
