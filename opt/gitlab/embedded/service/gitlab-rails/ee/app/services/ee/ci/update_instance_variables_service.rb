# frozen_string_literal: true

module EE
  module Ci
    module UpdateInstanceVariablesService
      extend ::Gitlab::Utils::Override

      private

      def instance_scope
        @instance_scope ||= ::Gitlab::Audit::InstanceScope.new
      end

      def audit_action(instance_variable)
        return :destroy if instance_variable.marked_for_destruction?

        instance_variable.previous_changes.key?(:id) ? :create : :update
      end

      override :audit_change
      def audit_change(instance_variable)
        ::Ci::AuditVariableChangeService.new(
          container: instance_scope,
          current_user: current_user,
          params: { action: audit_action(instance_variable), variable: instance_variable }
        ).execute
      end
    end
  end
end
