# frozen_string_literal: true

module RemoteDevelopment
  # noinspection RubyResolve -- https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-32336
  class WorkspaceVariablePolicy < BasePolicy
    condition(:can_read_workspace) { can?(:read_workspace, @subject.workspace) }

    rule { can_read_workspace }.enable :read_workspace_variable
  end
end
