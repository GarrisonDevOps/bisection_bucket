# frozen_string_literal: true

module Namespaces
  class TopLevelGroupLimit
    include ::Gitlab::Utils::StrongMemoize

    MAX_CREATOR_DEPTH = 10

    # One request can count one user while charging another, so a per-user actor could mix old and new rules.
    def self.enabled?
      ::Feature.enabled?(:top_level_group_creation_tracking, :instance)
    end

    def self.enforced_for?(account)
      return false unless ::Gitlab::Saas.feature_available?(:enforce_top_level_group_limits)
      return false unless ::Feature.enabled?(:enforce_top_level_group_limits, account)

      !account.exempt_from_top_level_group_limit?
    end

    def initialize(user)
      @user = user
    end

    def exceeded?
      return user.enforce_top_level_group_limit? unless self.class.enabled?
      return self.class.enforced_for?(user) if accountable_user.nil? || accountable_user.banned?

      accountable_user.enforce_top_level_group_limit?
    end

    def record_creation!(group)
      return unless self.class.enabled? && accountable_user

      ::Namespaces::TopLevelGroupsCreatedCount.new(accountable_user).increment!(group)
    end

    private

    attr_reader :user

    def accountable_user
      return user unless attribute_to_creator?

      candidate = user
      MAX_CREATOR_DEPTH.times do
        candidate = candidate.created_by
        return candidate if candidate.nil? || candidate.human?
      end

      nil
    end
    strong_memoize_attr :accountable_user

    def attribute_to_creator?
      user.service_account? && (user.provisioned_by_group_id || user.provisioned_by_project_id).present?
    end
  end
end
