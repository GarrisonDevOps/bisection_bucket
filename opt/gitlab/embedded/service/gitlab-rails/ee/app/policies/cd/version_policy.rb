# frozen_string_literal: true

module Cd
  class VersionPolicy < ::BasePolicy
    delegate { @subject.artifact_source }
  end
end
