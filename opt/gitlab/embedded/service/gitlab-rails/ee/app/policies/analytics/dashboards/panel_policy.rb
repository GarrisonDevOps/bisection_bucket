# frozen_string_literal: true

module Analytics
  module Dashboards
    class PanelPolicy < BasePolicy
      delegate { @subject.container }
    end
  end
end
