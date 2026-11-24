# frozen_string_literal: true

module Analytics
  module Dashboards
    class DashboardPolicy < BasePolicy
      delegate { @subject.container }
    end
  end
end
