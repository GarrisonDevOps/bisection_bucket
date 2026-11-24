# frozen_string_literal: true

module Security
  module Ascp
    class SecurityContextPolicy < BasePolicy
      delegate { @subject.project }
    end
  end
end
