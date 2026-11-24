# frozen_string_literal: true

module WorkItems
  # A bulk edit counts once against the bulk update limit and once per item against the issuable
  # update limit. Both bulk update services charge through here so the rules stay in one place.
  class BulkUpdateRateLimiter
    BULK_KEY = :work_item_bulk_update
    ITEM_KEY = :work_item_update

    TooManyItemsError = Class.new(StandardError)

    def initialize(user:, item_count:)
      @user = user
      @item_count = item_count
    end

    def check!
      # A batch over the limit could never pass, so it is refused before either counter is charged.
      limit = ::Gitlab::ApplicationRateLimiter.enforced_limit_for(ITEM_KEY, scope: scope)
      raise TooManyItemsError, too_many_items_message(limit) if limit > 0 && item_count > limit

      if ::Feature.enabled?(:work_item_bulk_update_rate_limit, user) && throttled?(BULK_KEY)
        raise_rate_limited!(BULK_KEY)
      end

      raise_rate_limited!(ITEM_KEY) if throttled?(ITEM_KEY, cost: item_count)
    end

    private

    attr_reader :user, :item_count

    def scope
      { user: user }
    end

    def too_many_items_message(limit)
      format(
        n_('No more than %{limit} item can be updated at the same time',
          'No more than %{limit} items can be updated at the same time', limit),
        limit: limit
      )
    end

    def throttled?(key, **opts)
      ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope, **opts)
    end

    def raise_rate_limited!(key)
      raise ::RateLimitedService::RateLimitedError.new(key: key, rate_limiter: ::Gitlab::ApplicationRateLimiter),
        ::Gitlab::ApplicationRateLimiter.throttled_error_message
    end
  end
end
