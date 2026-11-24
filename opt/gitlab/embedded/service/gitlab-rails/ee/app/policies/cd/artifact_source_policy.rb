# frozen_string_literal: true

module Cd
  class ArtifactSourcePolicy < ::BasePolicy
    delegate { @subject.service }
  end
end
