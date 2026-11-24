# frozen_string_literal: true

module Issuables
  class CustomFieldPolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
