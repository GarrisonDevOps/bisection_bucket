# frozen_string_literal: true

module Gitlab
  module EventsPlatform
    # The GitLab Events Bridge: a long-running process that consumes a Relay subscription and
    # re-publishes each event into Gitlab::EventStore, so existing subscribers handle it. Relay
    # redelivers any event that is not acknowledged, and an event is acknowledged only after
    # Gitlab::EventStore.publish returns. A stop can still land between a publish and its ack, so
    # an event can be delivered twice.
    #
    # The subscribe_events_from_relay feature flag is checked before each subscription, so
    # disabling it stops consumption at the next stream rotation, not immediately.
    #
    # Launched by bin/events-bridge. Call #stop from a signal handler to shut down.
    class Bridge
      DEFAULT_TOPIC = 'gitlab.events'
      DEFAULT_CONSUMER_GROUP = 'gitlab-events-bridge'

      # How long to wait before subscribing again when the feature flag is disabled or the
      # subscription ends without an error.
      RESUBSCRIBE_INTERVAL_SECONDS = 60

      # How often #run checks for a stop request while the consume thread works.
      STOP_CHECK_INTERVAL_SECONDS = 0.5

      # Raised into the consume thread to interrupt a stream that is blocked waiting for events.
      # An Interrupt, like Sidekiq::Shutdown, so a generic `rescue StandardError` does not catch it.
      ShutdownRequested = Class.new(Interrupt)

      def initialize(
        topic: DEFAULT_TOPIC,
        consumer_group: DEFAULT_CONSUMER_GROUP,
        client: nil,
        event_store: Gitlab::EventStore)
        @topic = topic
        @consumer_group = consumer_group
        @client = client
        @event_store = event_store
        @logger = Gitlab::EventsPlatform::Logger.build
        @stopping = false
        @in_flight = false
        @interrupted = false
        @mutex = Mutex.new
      end

      # Blocks until #stop is called. Raises when an event fails to bridge; that event is left
      # unacknowledged so Relay can deliver it again.
      def run
        log_info('events bridge starting')

        @consume_thread = Thread.new do
          # Set inside the thread so an early failure is not reported before #run re-raises it.
          Thread.current.report_on_exception = false
          subscribe_until_stopped
        end
        @consume_thread.name = 'events-bridge'

        interrupt_when_idle until @consume_thread.join(STOP_CHECK_INTERVAL_SECONDS)

        log_info('events bridge stopped')
      end

      # Safe to call from a signal handler: it only sets a flag, which #run acts on.
      def stop
        @stopping = true
      end

      private

      # Once a stop was requested, interrupts the consume thread only while no event is in flight.
      # Interrupting a publish could enqueue some subscribers and not others: connection_pool
      # re-enables interrupts inside Redis calls, so Thread.handle_interrupt cannot protect it.
      def interrupt_when_idle
        @mutex.synchronize do
          next if !@stopping || @in_flight || @interrupted

          @interrupted = true
          @consume_thread.raise(ShutdownRequested)
        end
      end

      def subscribe_until_stopped
        until @stopping
          subscribe
          next if @stopping

          sleep(RESUBSCRIBE_INTERVAL_SECONDS)
        end
      rescue ShutdownRequested
        log_info('events bridge shutting down')
      end

      def subscribe
        unless Feature.enabled?(:subscribe_events_from_relay, :instance)
          log_info('subscribe_events_from_relay feature flag is disabled; waiting')
          return
        end

        client.subscribe_events(
          topic: @topic,
          consumer_group: @consumer_group,
          stop_when: -> { @stopping || Feature.disabled?(:subscribe_events_from_relay, :instance) }
        ) do |proto_event|
          start_event

          begin
            bridge_event(proto_event)
          ensure
            @mutex.synchronize { @in_flight = false }
          end
        end
      end

      # Raises instead of starting an event once a stop was requested, so the event is left
      # unacknowledged.
      def start_event
        @mutex.synchronize do
          if @stopping
            @interrupted = true
            raise ShutdownRequested
          end

          @in_flight = true
        end
      end

      def bridge_event(proto_event)
        Rails.application.executor.wrap do
          event = Gitlab::EventStore::CloudEvent.from_proto(proto_event)
          @event_store.publish(event)

          # `type` is a reserved log key, hence the `event_` prefix.
          @logger.info(
            message: 'events bridge published event',
            topic: @topic,
            event_type: proto_event.type,
            event_id: proto_event.id
          )
        end
      rescue StandardError => e
        @logger.error(
          message: 'events bridge failed to publish event; event not acknowledged',
          topic: @topic,
          event_type: proto_event.type,
          event_id: proto_event.id,
          error_class: e.class.name,
          error_message: e.message
        )
        Gitlab::ErrorTracking.track_exception(e, event_type: proto_event.type, event_id: proto_event.id)

        raise
      end

      def client
        @client ||= Gitlab::Kas::Client.new
      end

      def log_info(message)
        @logger.info(message: message, topic: @topic, consumer_group: @consumer_group)
      end
    end
  end
end
