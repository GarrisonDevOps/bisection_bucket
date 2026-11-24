# frozen_string_literal: true

module Gitlab
  module Graphql
    module Subscriptions
      class ActionCableWithLoadBalancing < ::GraphQL::Subscriptions::ActionCableSubscriptions
        extend ::Gitlab::Utils::Override
        include Gitlab::Database::LoadBalancing::WalTrackingSender
        include Gitlab::Database::LoadBalancing::WalTrackingReceiver

        # A broadcast that graphql-ruby's stream handler has not loaded yet. `execute_update` decides whether to
        # load and run it now, or to keep it for the end of a coalescing window.
        UnloadedMessage = Data.define(:message, :context)

        # graphql-ruby's own loader. Calling it directly, not through `super_method`, keeps a deferred update from
        # reaching `load_action_cable_message` again if something ever overrides it above this class.
        GRAPHQL_LOADER = ::GraphQL::Subscriptions::ActionCableSubscriptions.instance_method(:load_action_cable_message)

        def initialize(...)
          super

          @coalescer = Coalescer.new(merge: Envelope.method(:merge))
          @coalesce_policies = Concurrent::Map.new
        end

        def coalescer_size
          @coalescer.size
        end

        override :trigger
        def trigger(event_name, args, object, **options)
          return super unless rate_limit_policy(event_name)&.throttled?(args, object)

          DroppedEvents.count(event_name, :rate_limited)
          nil
        end

        override :execute_all
        def execute_all(event, object)
          envelope = Envelope.wrap(
            object,
            wal_locations: current_wal_locations,
            correlation_id: ::Labkit::Correlation::CorrelationId.current_id
          )

          super(event, envelope.to_h)
        end

        # graphql-ruby's stream handler is the only caller, and it passes the result straight to `execute_update`.
        # Loading waits until the update runs, so a message that the coalescer keeps costs no record lookup.
        override :load_action_cable_message
        def load_action_cable_message(message, context)
          UnloadedMessage.new(message, context)
        end

        override :execute_update
        def execute_update(subscription_id, event, object)
          if object.is_a?(UnloadedMessage)
            envelope = Envelope.parse(object.message)
            return if kept_for_later?(event, envelope)

            object = load_message(object.message, object.context, envelope)
          end

          return super(subscription_id, event, object) unless Envelope.wrapped?(object)

          super(subscription_id, event, Envelope.new(object).payload)
        end

        private

        # An unknown field returns nil here, so that `super` raises graphql-ruby's own error for it.
        def rate_limit_policy(event_name)
          subscription_class(event_name)&.rate_limit_policy
        end

        def subscription_class(event_name)
          @schema.subscription.get_field(normalize_name(event_name))&.resolver
        end

        def run_update(events, object)
          first_event = events.first
          result = execute_update(first_event.context.fetch(:subscription_id), first_event, object)
          return if result.nil?

          events.each { |event| deliver(event.context.fetch(:subscription_id), result) }
        end

        # The payload carries global IDs, so loading it is what turns them back into records.
        # The fallback to the primary has to be decided before that lookup, or it can
        # miss a row the replica has not received yet.
        def load_message(message, context, envelope = Envelope.parse(message))
          apply_primary_fallback(envelope)

          GRAPHQL_LOADER.bind_call(self, message, context)
        end

        # The envelope is parsed without loading its payload, so this decision runs no database query.
        # An error here must not lose the update, so the update then runs at once.
        def kept_for_later?(event, envelope)
          policy = coalesce_policy(event.name)
          return false unless policy && envelope&.record_id && policy.enabled_for?(event.context[:current_user])

          key = Coalescer::Key.new(topic: event.topic, fingerprint: event.fingerprint, record: envelope.record_id)
          outcome = @coalescer.submit(key, envelope, window: policy.window) do |latest|
            dispatch_deferred_update(event, latest)
          end
          CoalescedEvents.count(event.name, outcome)

          outcome == :deferred
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e)
          false
        end

        # A field's policy never changes, so each field is looked up once. `compute_if_absent` caches nil too.
        def coalesce_policy(event_name)
          @coalesce_policies.compute_if_absent(event_name) { subscription_class(event_name).coalesce_policy }
        end

        # `fetch` does not create entries in graphql-ruby's map, unlike `[]`.
        def subscribers_of(event)
          @events.fetch(event.topic, nil)&.fetch(event.fingerprint, nil)
        end

        # Called on the coalescer's scheduler thread, which must not run queries. The worker pool runs the update
        # with the same callbacks as an update that arrives from Redis.
        def dispatch_deferred_update(event, envelope)
          connection = event.context.fetch(:channel).connection
          connection.worker_pool.async_invoke(
            self, :run_deferred_update, event, ::Gitlab::Json.dump(envelope.to_h), connection: connection
          )
        end

        # The subscriber that received the burst can be gone by now, so this runs for the current subscribers of
        # the fingerprint.
        def run_deferred_update(event, message)
          events = subscribers_of(event)
          return if events.blank?

          CoalescedEvents.count(event.name, :flushed)
          run_update(events, load_message(message, events.first.context))
        end

        def use_primary!
          ::Gitlab::Database::LoadBalancing::SessionMap
            .with_sessions(Gitlab::Database::LoadBalancing.base_models)
            .use_primary!
        end

        def apply_primary_fallback(envelope)
          return unless envelope

          locations = envelope.wal_locations || {}
          return unless use_primary?(locations)

          use_primary!

          ::Gitlab::Database::LoadBalancing::Logger.info(
            event: :graphql_subscription_primary_fallback,
            fallback_reason: fallback_reason(envelope, locations),
            ::Labkit::Fields::CORRELATION_ID => envelope.correlation_id
          )
        end

        def fallback_reason(envelope, locations)
          return :envelope_unreadable unless envelope.readable?
          return :wal_locations_absent if locations.blank?

          :replicas_behind
        end

        def use_primary?(wal_locations)
          wal_locations.blank? || !databases_in_sync?(wal_locations)
        end

        # We stringify keys since otherwise the graphql-ruby serializer will inject additional metadata
        # to keep track of which keys used to be symbols.
        def current_wal_locations
          wal_locations_by_db_name&.stringify_keys
        end
      end
    end
  end
end
