# frozen_string_literal: true

module Security
  class ScanResultPoliciesFinder < SecurityPolicyBaseFinder
    def initialize(actor, object, params = {})
      super(actor, object, :scan_result_policies, params)
    end
  end
end
