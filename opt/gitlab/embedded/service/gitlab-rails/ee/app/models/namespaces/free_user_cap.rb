# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    REACHED_LIMIT_VARIANT = 'reached'
    CLOSE_TO_LIMIT_VARIANT = 'close'

    def self.dashboard_limit
      ::Gitlab::CurrentSettings.dashboard_limit
    end

    def self.dashboard_limit_enabled?
      ::Gitlab::CurrentSettings.dashboard_limit_enabled?
    end

    def self.can_read_billable_members?(user:, namespace:)
      return false unless user

      Ability.allowed?(user, :read_billable_member, namespace)
    end

    def self.non_owner_access?(user:, namespace:)
      return false unless user
      return false if can_read_billable_members?(user: user, namespace: namespace)

      Ability.allowed?(user, :read_group, namespace)
    end

    def self.enforced_without_storage_check?(namespace)
      return false unless Feature.enabled?(:free_user_cap_without_storage_check, namespace)

      ::Namespaces::FreeUserCap::RootSize.new(namespace).above_size_limit?
    end
  end
end

Namespaces::FreeUserCap.prepend_mod
