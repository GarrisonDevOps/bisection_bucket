# frozen_string_literal: true

module Security
  class ScanProfilePolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
