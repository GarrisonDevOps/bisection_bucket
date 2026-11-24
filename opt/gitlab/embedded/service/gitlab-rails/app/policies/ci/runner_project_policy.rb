# frozen_string_literal: true

module Ci
  class RunnerProjectPolicy < BasePolicy
    delegate(:project) { @subject.project }

    with_options scope: :subject, score: 10
    condition(:locked) { @subject.runner.locked? }

    with_options scope: :subject, score: 12
    condition(:assigned_to_owner_project) { @subject.project == @subject.runner.owner }

    rule { anonymous }.prevent_all

    rule { ~admin & locked }.prevent :unassign_runner

    rule { assigned_to_owner_project }.prevent :unassign_runner
  end
end

Ci::RunnerProjectPolicy.prepend_mod
