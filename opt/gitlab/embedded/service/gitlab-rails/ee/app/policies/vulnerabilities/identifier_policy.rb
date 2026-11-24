# frozen_string_literal: true

module Vulnerabilities
  class IdentifierPolicy < BasePolicy
    delegate { @subject.project }
  end
end
