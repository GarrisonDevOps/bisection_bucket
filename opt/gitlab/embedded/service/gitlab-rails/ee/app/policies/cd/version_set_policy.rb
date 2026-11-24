# frozen_string_literal: true

module Cd
  class VersionSetPolicy < ::BasePolicy
    delegate { @subject.application }
  end
end
