# frozen_string_literal: true

module Security
  class ProjectSecurityExclusionPolicy < BasePolicy
    delegate { @subject.project }
  end
end
