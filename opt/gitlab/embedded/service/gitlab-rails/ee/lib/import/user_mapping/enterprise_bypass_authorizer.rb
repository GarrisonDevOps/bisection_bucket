# frozen_string_literal: true

module Import
  module UserMapping
    class EnterpriseBypassAuthorizer
      def initialize(group, assignee_user, reassigned_by_user)
        @group = group.root_ancestor
        @assignee_user = assignee_user
        @reassigned_by_user = reassigned_by_user
      end

      def allowed?
        Ability.allowed?(reassigned_by_user, :admin_namespace, group) &&
          group.namespace_settings.enterprise_placeholder_bypass_enabled? &&
          assignee_user.managed_by_group?(group)
      end

      private

      attr_reader :group, :assignee_user, :reassigned_by_user
    end
  end
end
