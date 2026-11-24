# frozen_string_literal: true

module Security
  module Ascp
    class ComponentPolicy < BasePolicy
      delegate { @subject.project }
    end
  end
end
