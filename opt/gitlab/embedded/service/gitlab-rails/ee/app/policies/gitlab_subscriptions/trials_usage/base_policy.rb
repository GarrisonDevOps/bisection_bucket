# frozen_string_literal: true

module GitlabSubscriptions
  module TrialsUsage
    class BasePolicy < ::BasePolicy
      delegate { @subject.declarative_policy_subject }
    end
  end
end
