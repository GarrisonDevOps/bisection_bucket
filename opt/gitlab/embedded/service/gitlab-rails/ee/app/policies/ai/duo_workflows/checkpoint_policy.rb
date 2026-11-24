# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CheckpointPolicy < BasePolicy
      condition(:can_read_duo_workflow) do
        can?(:read_duo_workflow, @subject.workflow)
      end

      rule { can_read_duo_workflow }.policy do
        enable :read_duo_workflow_event
      end
    end
  end
end
