# frozen_string_literal: true

module Security
  class AnalyzerNamespaceStatusPolicy < BasePolicy
    delegate { @subject.group }
  end
end
