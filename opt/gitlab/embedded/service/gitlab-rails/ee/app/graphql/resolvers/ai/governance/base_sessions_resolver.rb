# frozen_string_literal: true

module Resolvers
  module Ai
    module Governance
      # Shared resolution for AI governance sessions. The group resolver adds `project_path`;
      # the project resolver omits it because the parent object fixes the project.
      class BaseSessionsResolver < ::Resolvers::BaseResolver
        type ::Types::Ai::Governance::SessionType.connection_type, null: true

        # Every listing reads at most this span, so the ClickHouse dedup and the count never grow
        # with a namespace's whole history. A lookup by `id` matches one row and needs no window.
        MAX_WINDOW = 180.days

        argument :id, ::Types::GlobalIDType[::Ai::Governance::Session],
          required: false,
          description: 'Global ID of the session. No default time window applies when given.'

        argument :flow_type, GraphQL::Types::String,
          required: false,
          description: 'Filter by flow type.'

        argument :agent_class, ::Types::Ai::Governance::AgentClassEnum,
          required: false,
          description: 'Filter sessions by agent class. Defaults to all agent classes.'

        argument :session_started_after, ::Types::TimeType,
          required: false,
          description: 'Return sessions started at or after the timestamp. Defaults to 180 days before ' \
            '`sessionStartedBefore`, or before now, and is moved up to that bound when it is earlier.'

        argument :session_started_before, ::Types::TimeType,
          required: false,
          description: 'Return sessions started at or before the timestamp. Defaults to now.'

        argument :triggered_by_user_id, ::Types::GlobalIDType[::User],
          required: false,
          description: 'Filter to sessions triggered by the user with the given global ID.'

        argument :not, ::Types::Ai::Governance::SessionNegatedFilterInput,
          required: false,
          description: 'Negated filter conditions.'

        def resolve(**args)
          if args[:session_started_after] && args[:session_started_before] &&
              args[:session_started_after] > args[:session_started_before]
            raise Gitlab::Graphql::Errors::ArgumentError,
              'sessionStartedAfter must not be after sessionStartedBefore'
          end

          return ::Ai::Governance::Session.none unless feature_enabled?

          raise_resource_not_available_error!(::Gitlab::ApplicationRateLimiter.throttled_error_message) if rate_limited?

          finder_args = { current_user: current_user, namespace: resolver_namespace, params: finder_params(args) }

          return ::Ai::Governance::Sessions::ClickHouseFinder.new(**finder_args).execute if click_house_enabled?

          finder = ::Ai::Governance::SessionsFinder.new(**finder_args)

          # The in-operator optimized relation hides its ordering inside a recursive CTE, so the
          # keyset connection would fall back to ordering by `id`. Offset pagination keeps the order.
          # SessionConnectionType counts with `count_relation` instead of the in-operator relation.
          offset_pagination(finder.execute).tap do |relation|
            relation.define_singleton_method(:count_relation) { finder.count_relation }
          end
        end

        private

        def finder_params(args)
          {
            id: args[:id]&.model_id&.to_i,
            flow_type: args[:flow_type],
            agent_class: args[:agent_class],
            session_started_after: bounded_session_started_after(args),
            session_started_before: args[:session_started_before],
            user_id: args[:triggered_by_user_id]&.model_id&.to_i,
            not: prepare_not_args(args[:not])
          }.compact
        end

        def resolver_namespace
          raise NotImplementedError
        end

        # The floor starts from now at the latest, so a future `sessionStartedBefore` keeps recent sessions.
        #
        # @param args [Hash] resolver arguments
        # @return [Time, nil] start of the window, or the caller's value for an `id` lookup
        def bounded_session_started_after(args)
          return args[:session_started_after] if args[:id]

          floor = [args[:session_started_before], Time.current].compact.min - MAX_WINDOW
          [args[:session_started_after], floor].compact.max
        end

        # Renames the negated user global ID to the `user_id` column the finder filters on.
        def prepare_not_args(not_arg)
          not_arg&.to_h&.tap do |not_hash|
            triggered_by_user_id = not_hash.delete(:triggered_by_user_id)
            not_hash[:user_id] = triggered_by_user_id.model_id.to_i if triggered_by_user_id
          end
        end

        def feature_enabled?
          ::Feature.enabled?(:ai_governance_sessions_api, object.root_ancestor)
        end

        # Counted per user and top-level namespace before any finder runs, so an over-limit call
        # costs no ClickHouse or PostgreSQL query.
        def rate_limited?
          return false unless ::Feature.enabled?(:ai_governance_rate_limits, object.root_ancestor)

          ::Gitlab::ApplicationRateLimiter.throttled?(
            :ai_governance_sessions_api, scope: { user: current_user, namespace: object.root_ancestor }
          )
        end

        def click_house_enabled?
          ::Gitlab::ClickHouse.globally_enabled_for_analytics?
        end
      end
    end
  end
end
