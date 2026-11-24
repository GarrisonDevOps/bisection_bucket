# frozen_string_literal: true

module EE
  module Ci
    module RunnerPolicy
      extend ActiveSupport::Concern

      prepended do
        # Runners GitLab operates for a GitLab Dedicated tenant.
        with_scope :subject
        condition(:dedicated_hosted_runner) { @subject.gitlab_operated_hosted_runner? }

        rule { auditor }.policy do
          enable :read_runner
          enable :read_runner_job
        end

        rule { dedicated_hosted_runner }.prevent :reset_runner_authentication_token
      end
    end
  end
end
