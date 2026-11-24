# frozen_string_literal: true

module Vulnerabilities
  class NamespaceStatisticPolicy < BasePolicy
    delegate { @subject.group }
  end
end
