# frozen_string_literal: true

module Ci
  module Minutes
    class NamespaceMonthlyUsagePolicy < BasePolicy
      delegate { @subject.namespace }

      rule { can?(:admin_namespace) }.enable :read_usage
    end
  end
end
