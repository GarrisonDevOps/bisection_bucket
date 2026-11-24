# frozen_string_literal: true

module Vulnerabilities
  class StatisticPolicy < BasePolicy
    delegate { @subject.project }
  end
end
