# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class SystemDashboardPolicy < BasePolicy
      # Deliberately not `scope: :subject`. A subject-scoped condition is cached
      # across users, and the `feature_flag` constraint is checked per user and
      # the root groups they belong to.
      condition(:constraints_satisfied) do
        DashboardConstraints.satisfied?(@subject, @user)
      end

      rule { ~anonymous }.enable :read_system_dashboard
      rule { ~constraints_satisfied }.prevent :read_system_dashboard
    end
  end
end
