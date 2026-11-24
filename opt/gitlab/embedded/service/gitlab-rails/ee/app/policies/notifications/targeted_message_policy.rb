# frozen_string_literal: true

module Notifications
  class TargetedMessagePolicy < BasePolicy
    condition(:can_read_associated_namespace) do
      @subject.namespaces.any? { |namespace| can?(:read_namespace, namespace) }
    end

    rule { can_read_associated_namespace }.enable :read_namespace
  end
end
