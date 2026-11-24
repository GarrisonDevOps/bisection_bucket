# frozen_string_literal: true

module Ai
  class NamespaceSettingPolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
