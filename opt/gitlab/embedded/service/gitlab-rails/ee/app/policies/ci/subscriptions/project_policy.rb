# frozen_string_literal: true

module Ci
  module Subscriptions
    class ProjectPolicy < BasePolicy
      condition(:admin_upstream_project) do
        can?(:admin_project, @subject.upstream_project)
      end

      condition(:admin_downstream_project) do
        can?(:admin_project, @subject.downstream_project)
      end

      rule { admin_upstream_project }.policy do
        enable :read_project_subscription
      end

      rule { admin_downstream_project }.policy do
        enable :read_project_subscription
        enable :delete_project_subscription
      end
    end
  end
end
