# frozen_string_literal: true

module Ai
  class FlowSchedulePolicy < ::BasePolicy
    delegate { @subject.project }
  end
end
