# frozen_string_literal: true

module Analytics
  module Dashboards
    class VisualizationPolicy < BasePolicy
      delegate { @subject.container }
    end
  end
end
