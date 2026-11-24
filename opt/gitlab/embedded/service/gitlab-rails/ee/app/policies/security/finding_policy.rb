# frozen_string_literal: true
module Security
  class FindingPolicy < BasePolicy
    delegate { @subject.scan }
  end
end
