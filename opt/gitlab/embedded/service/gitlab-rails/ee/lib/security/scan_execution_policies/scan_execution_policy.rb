# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class ScanExecutionPolicy < Security::BaseSecurityPolicy
      def actions
        Security::ScanExecutionPolicies::Actions.new(policy_content[:actions] || [])
      end

      def skip_ci
        Security::ScanExecutionPolicies::SkipCi.new(policy_content[:skip_ci] || {})
      end

      def rules
        Security::ScanExecutionPolicies::Rules
          .new(policy_record.rules.map(&:typed_content).map(&:deep_symbolize_keys) || [])
      end

      private

      def policy_content
        policy_record.policy_content
      end
    end
  end
end
