# frozen_string_literal: true

module Security
  class AllPoliciesFinder < SecurityPolicyBaseFinder
    extend ::Gitlab::Utils::Override

    def initialize(actor, object, params = {})
      super(actor, object, :all_policies, params)
    end
  end
end
