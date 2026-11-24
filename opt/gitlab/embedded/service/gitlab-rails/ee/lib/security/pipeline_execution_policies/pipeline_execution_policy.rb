# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class PipelineExecutionPolicy < Security::BaseSecurityPolicy
      def content
        Security::PipelineExecutionPolicies::Content.new(policy_content[:content] || {})
      end

      def pipeline_config_strategy
        policy_content[:pipeline_config_strategy]
      end

      def suffix
        policy_content[:suffix]
      end

      def skip_ci
        Security::PipelineExecutionPolicies::SkipCi.new(policy_content[:skip_ci] || {})
      end

      def variables_override
        Security::PipelineExecutionPolicies::VariablesOverride.new(policy_content[:variables_override] || {})
      end

      private

      def policy_content
        policy_record.policy_content
      end
    end
  end
end
