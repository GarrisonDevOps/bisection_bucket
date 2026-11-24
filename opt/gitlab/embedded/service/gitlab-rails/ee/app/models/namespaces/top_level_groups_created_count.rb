# frozen_string_literal: true

module Namespaces
  class TopLevelGroupsCreatedCount
    METRIC = :top_level_groups_created_count

    def initialize(user)
      @user = user
    end

    def value
      return live_count unless ::Namespaces::TopLevelGroupLimit.enabled?

      stored = ::AntiAbuse::UserMetadata.metric(user.id, METRIC)
      return stored if stored

      live = live_count
      ::AntiAbuse::UserMetadata.initialize_metric(user.id, METRIC, live)
      live
    end

    def increment!(group)
      return unless ::Namespaces::TopLevelGroupLimit.enabled?

      stored = ::AntiAbuse::UserMetadata.metric(user.id, METRIC)
      return if stored.nil? && !::Namespaces::TopLevelGroupLimit.enforced_for?(user)

      initial = stored || live_count(excluding: group)

      ::AntiAbuse::UserMetadata.increment_metric(user.id, METRIC, initial: initial)
    end

    private

    attr_reader :user

    def live_count(excluding: nil)
      scope = user.created_namespace_details.joins(:namespace).where(namespaces: { parent: nil, type: 'Group' })
      scope = scope.where.not(namespace_id: excluding.id) if excluding
      scope.count
    end
  end
end
