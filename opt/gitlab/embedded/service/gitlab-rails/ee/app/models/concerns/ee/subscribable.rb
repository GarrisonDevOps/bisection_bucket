# frozen_string_literal: true

module EE
  module Subscribable # rubocop:disable Gitlab/BoundedContexts -- needs refactoring of all instances of Subscribable
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    override :lazy_subscription
    def lazy_subscription(user, project = nil, cache_enforced: true)
      return super unless try(:unified_associations?)

      BatchLoader.for(batched_object).batch(cache: false) do |ids, loader, _args|
        subscriptions = unified_subscriptions(ids.map(&:first), ids.map(&:second), user)

        ids.each do |ids_pair|
          # If two subscriptions for this user exist (in the epic and the synced work item) only one will have a value
          # because we select the latest one in unified_subscriptions.
          loader.call(ids_pair, [subscriptions[ids_pair[0]], subscriptions[ids_pair[1]]].flatten.compact.first)
        end
      end
    end
  end
end # rubocop:enable Gitlab/BoundedContexts
