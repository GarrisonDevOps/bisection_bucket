# frozen_string_literal: true

module Subscriptions
  class BaseSubscription < GraphQL::Schema::Subscription
    include Gitlab::Graphql::VersionFilter::FutureFieldFallback

    object_class Types::BaseObject
    field_class Types::BaseField

    UNAUTHORIZED_ERROR_MESSAGE = 'Unauthorized subscription'

    class_attribute :rate_limit_policy, :coalesce_policy, instance_accessor: false, instance_predicate: false

    # Gitlab::Graphql::Subscriptions::ActionCableWithLoadBalancing#trigger enforces it.
    def self.rate_limit(key, scope:)
      self.rate_limit_policy = Gitlab::Graphql::Subscriptions::RateLimitPolicy.new(key, scope)
    end

    # Only for subscriptions whose payload is the current state of one record: within `window`, the websocket
    # node sends the first update for that record and then only the newest one. See
    # Gitlab::Graphql::Subscriptions::Coalescer.
    def self.coalesce(window: 0.5.seconds)
      self.coalesce_policy = Gitlab::Graphql::Subscriptions::CoalescePolicy.new(window)
    end

    def initialize(object:, context:, field:)
      super

      # Reset so long-lived subscriptions don't authorize against stale membership or token scope
      current_user.reset if current_user
      access_token.reset if access_token.respond_to?(:reset)
    end

    # Subscriptions return no initial payload; Vue components fetch initial
    # state with a query. GraphqlChannel does not transmit this empty result.
    # See https://gitlab.com/gitlab-org/gitlab/-/issues/402614
    def subscribe(*)
      nil
    end

    def authorized?(*)
      raise NotImplementedError
    end

    private

    def authorize_object_or_gid!(ability_name, gid:, object: self.object)
      auth_object = object.presence || force(GitlabSchema.find_by_gid(gid))

      return unauthorized! if auth_object.nil?

      unauthorized! unless Ability.allowed?(current_user, ability_name, auth_object)

      true
    end

    def unauthorized!
      unsubscribe if context.query.subscription_update?

      raise GraphQL::ExecutionError, UNAUTHORIZED_ERROR_MESSAGE
    end

    def current_user
      context[:current_user]
    end

    def access_token
      context[:access_token]
    end
  end
end
