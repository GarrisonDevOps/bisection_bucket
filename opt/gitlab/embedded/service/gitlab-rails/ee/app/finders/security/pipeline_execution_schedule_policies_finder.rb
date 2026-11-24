# frozen_string_literal: true

module Security
  class PipelineExecutionSchedulePoliciesFinder < SecurityPolicyBaseFinder
    extend ::Gitlab::Utils::Override

    def initialize(actor, object, params = {})
      super(actor, object, :pipeline_execution_schedule_policy, params)
    end
  end
end
