# frozen_string_literal: true

module Security
  class PipelineExecutionPoliciesFinder < SecurityPolicyBaseFinder
    extend ::Gitlab::Utils::Override

    def initialize(actor, object, params = {})
      super(actor, object, :pipeline_execution_policy, params)
    end
  end
end
