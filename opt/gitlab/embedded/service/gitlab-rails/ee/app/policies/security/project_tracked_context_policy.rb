# frozen_string_literal: true

module Security
  class ProjectTrackedContextPolicy < BasePolicy
    delegate { @subject.project }
  end
end
