# frozen_string_literal: true

module Ci
  module Minutes
    class GitlabHostedRunnerMonthlyUsagePolicy < BasePolicy
      delegate { :global }
    end
  end
end
