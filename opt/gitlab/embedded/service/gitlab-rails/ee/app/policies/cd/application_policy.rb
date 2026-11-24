# frozen_string_literal: true

module Cd
  class ApplicationPolicy < ::BasePolicy
    delegate { @subject.organization }
  end
end
