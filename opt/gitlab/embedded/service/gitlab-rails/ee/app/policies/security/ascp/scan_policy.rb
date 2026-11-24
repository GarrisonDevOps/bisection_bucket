# frozen_string_literal: true

module Security
  module Ascp
    class ScanPolicy < BasePolicy
      delegate { @subject.project }
    end
  end
end
