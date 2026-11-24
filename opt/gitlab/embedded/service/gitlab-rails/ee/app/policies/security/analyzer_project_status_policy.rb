# frozen_string_literal: true

module Security
  class AnalyzerProjectStatusPolicy < BasePolicy
    delegate { @subject.project }
  end
end
