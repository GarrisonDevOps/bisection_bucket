# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Mirrors CheckpointPolicy: WorkflowPresenter#latest_checkpoint/#first_checkpoint can
    # return either a Checkpoint or a CheckpointHeader row, and DeclarativePolicy resolves
    # by the subject's exact class, so both need an equivalent policy registered.
    class CheckpointHeaderPolicy < BasePolicy
      condition(:can_read_duo_workflow) do
        can?(:read_duo_workflow, @subject.workflow)
      end

      rule { can_read_duo_workflow }.policy do
        enable :read_duo_workflow_event
      end
    end
  end
end
