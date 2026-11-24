# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Policy for every join model that includes `WorkflowLinkable`. A link is
    # readable exactly when its session is, so reuse the workflow's policy.
    class WorkflowLinkPolicy < BasePolicy
      delegate { @subject.workflow }
    end
  end
end
