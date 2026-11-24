# frozen_string_literal: true

module Vulnerabilities
  class FlagPolicy < BasePolicy
    delegate { @subject.finding }
  end
end
