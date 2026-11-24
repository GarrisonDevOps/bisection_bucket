# frozen_string_literal: true

module EventForward
  class EventForwardController < BaseActionController
    include SessionlessAuthentication

    DEDICATED_SUFFIX = 'dedicated'
    SELF_MANAGED_SUFFIX = 'sm'
    EDITOR_TELEMETRY_HEADER = 'HTTP_X_GITLAB_EDITOR_TELEMETRY'
    CONTEXTS_SCHEMA_URL = 'iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1'
    STANDARD_SCHEMA_URL = Gitlab::Tracking::StandardContext::GITLAB_STANDARD_SCHEMA_URL
    STANDARD_SCHEMA_PREFIX = 'iglu:com.gitlab/gitlab_standard/jsonschema/'

    before_action :authenticate_sessionless_user!, if: :editor_extension_request?
    before_action :prevent_session_extension

    def forward
      process_events
      head :ok
    end

    private

    # Telemetry beacons authenticate through the session but must not refresh its expiry.
    # A page that pings on a heartbeat (Snowplow activity tracking) would otherwise keep its
    # session alive indefinitely, defeating inactivity-based session expiry.
    def prevent_session_extension
      request.session_options[:skip] = true
    end

    def authenticate_sessionless_user!
      super(:editor_extension)
    end

    # BaseActionController has no render_404, so respond with a forbidden status.
    def deny_granular_token!
      head :forbidden
    end

    def process_events
      tracker = Gitlab::Tracking.tracker
      event_eligibility_checker = Gitlab::Tracking::EventEligibilityChecker.new

      payload = Gitlab::Json.safe_parse(request.raw_post)

      events_to_forward = payload['data'].select do |event|
        event_eligibility_checker.eligible?(event['se_ac'], event['aid'])
      end

      events_to_forward.each do |event|
        update_app_id(event)
        enrich_with_standard_context(event) if editor_extension_request?
        tracker.emit_event_payload(event)
        validate_contexts(event) if Rails.env.development?
      end

      logger.info("Enqueued events for forwarding. Count: #{events_to_forward.size}")
    end

    def validate_contexts(event)
      return unless event['cx']

      context_payload = decode_contexts(event['cx'])
      return unless context_payload

      Gitlab::Tracking::Destinations::SnowplowContextValidator.new.validate!(context_payload['data'])
    end

    def editor_extension_request?
      request.env[EDITOR_TELEMETRY_HEADER].present?
    end

    def update_app_id(event)
      app_id = event['aid']

      return unless app_id
      return if app_id.ends_with?(suffix)

      event['aid'] = "#{app_id}#{suffix}"
    end

    def enrich_with_standard_context(event)
      context_payload = decode_contexts(event['cx'])
      # Forward contexts we cannot read as the client sent them.
      return unless context_payload

      standard_contexts, other_contexts = context_payload['data'].partition { |ctx| gitlab_standard_context?(ctx) }

      # Consumers read the first gitlab_standard context, so a client one of any version must not stay next to ours.
      context_payload['data'] = other_contexts << server_standard_context(standard_contexts.first)

      event['cx'] = Base64.strict_encode64(Gitlab::Json.dump(context_payload))
    end

    def decode_contexts(encoded_contexts)
      return { 'schema' => CONTEXTS_SCHEMA_URL, 'data' => [] } if encoded_contexts.blank?
      return unless encoded_contexts.is_a?(String)

      # Snowplow trackers send URL-safe base64 without padding. This also decodes standard base64.
      context_payload = Gitlab::Json.safe_parse(Base64.urlsafe_decode64(encoded_contexts))
      context_payload if readable_contexts?(context_payload)
    rescue JSON::ParserError, ArgumentError
      nil
    end

    def readable_contexts?(context_payload)
      return false unless context_payload.is_a?(Hash) && context_payload['data'].is_a?(Array)

      context_payload['data'].all? { |context| context.is_a?(Hash) && context['data'].is_a?(Hash) }
    end

    def gitlab_standard_context?(context)
      context['schema'].to_s.start_with?(STANDARD_SCHEMA_PREFIX)
    end

    def server_standard_context(client_context)
      data = Gitlab::Tracking::StandardContext.new(user: current_user).to_h
      client_data = client_context ? client_context['data'] : {}
      # The client knows which extension sent the event, and the Language Server puts event properties in extra.
      data[:source] = client_data['source'] if client_data['source'].is_a?(String)
      data[:extra] = client_data['extra'] if client_data['extra'].is_a?(Hash)

      { 'schema' => STANDARD_SCHEMA_URL, 'data' => data }
    end

    def logger
      @logger ||= EventForward::Logger.build
    end

    def suffix
      @suffix ||= if Gitlab::Tracking::Destinations::Snowplow.dedicated?
                    "_#{DEDICATED_SUFFIX}"
                  else
                    "_#{SELF_MANAGED_SUFFIX}"
                  end
    end
  end
end
