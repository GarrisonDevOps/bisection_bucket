# frozen_string_literal: true

module Ai
  class FeatureAccessRuleAuditor
    def initialize(current_user:, rules:, scope:)
      @current_user = current_user
      @rules = rules
      @scope = scope
    end

    attr_reader :current_user, :rules, :scope

    def execute
      ::Gitlab::Audit::Auditor.audit(
        name: event_name,
        author: current_user,
        scope: scope,
        target: target,
        message: message
      )
    end

    private

    def event_name
      return 'feature_access_rules_updated' if instance_scope?

      'namespace_feature_access_rules_updated'
    end

    def target
      return ::Gitlab::Audit::NullTarget.new if instance_scope?

      scope
    end

    def instance_scope?
      scope.is_a?(::Gitlab::Audit::InstanceScope)
    end

    def message
      return 'Cleared feature access rules' if rules.empty?

      updated_rules = rules.map do |rule|
        group_id = rule.dig(:through_namespace, :id) || 'default'
        "Group id: #{group_id}, features: #{rule[:features]}"
      end.join('; ')

      "Updated feature access rules #{updated_rules}"
    end
  end
end
