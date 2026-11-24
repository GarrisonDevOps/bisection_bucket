# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Read-only client for Anthropic's Compliance API local session endpoints. Needs a
      # Compliance Access Key with `read:compliance_user_data`. The default retries sleep,
      # so they suit Sidekiq; web callers pass a short `timeout` and `max_attempts: 1`.
      #
      # https://platform.claude.com/docs/en/manage-claude/compliance-sessions
      class Client
        BASE_URL = 'https://api.anthropic.com/v1/compliance'
        SESSIONS_PATH = '/apps/sessions/local'
        TIMEOUT = 30.seconds

        MAX_RESPONSE_SIZE = 20.megabytes

        MAX_SESSIONS_LIMIT = 500
        MAX_MESSAGES_LIMIT = 1000
        MESSAGE_ORDERS = %w[asc desc].freeze

        MAX_ATTEMPTS = 3
        INITIAL_BACKOFF = 1.second
        MAX_BACKOFF = 10.seconds

        JITTER = 0.25

        # A restart issues a fresh cursor, so a second expiry means something else is wrong.
        MAX_CURSOR_RESTARTS = 1

        MAX_PAGES = 1_000

        # Everything else in HTTP_ERRORS is a connection blip worth another attempt.
        PERMANENT_TRANSPORT_ERRORS = [
          ::Gitlab::HTTP::BlockedUrlError,
          ::Gitlab::HTTP::RedirectionTooDeep,
          ::Gitlab::HTTP::ResponseSizeTooLarge,
          ::Gitlab::HTTP::MaxDecompressionSizeError,
          ::Gitlab::HTTP::InvalidResponseError
        ].freeze

        # Anthropic reuses one error type across these conditions; the message text is the
        # only discriminator.
        LOCAL_SESSIONS_UNAVAILABLE = 'Local sessions are not available'
        SESSION_NOT_FOUND = 'Local session not found'
        EXPIRED_CURSOR = 'page cursor has expired'
        RETENTION_OVERRIDES_UNAVAILABLE = 'evaluate retention overrides'
        CAPTURED_CONTENT_UNAVAILABLE = 'Captured content is temporarily unavailable'

        # Anthropic truncates tool blocks at 10,000 bytes by default, cutting a tool_use
        # input mid-document so it is no longer valid JSON.
        TOOL_BYTES_SERVER_MAX = -1
        MAX_TOOL_BYTES = 2_147_483_647

        # Without an offset a timestamp reads as server-local, shifting the export window.
        UTC_OFFSET = /(?:Z|[+-]\d{2}:\d{2})\z/

        # `session` is the messages endpoint's envelope, carrying the attribution an audit
        # record needs. Nil on the list endpoint.
        Page = Struct.new(:data, :next_page, :session, :rate_limit, keyword_init: true)

        RateLimit = Struct.new(:limit, :remaining, :reset_at, keyword_init: true)

        class Error < StandardError
          attr_reader :request_id

          def initialize(message, request_id: nil)
            @request_id = request_id

            super(message)
          end
        end

        MissingApiKeyError = Class.new(Error)

        InvalidApiKeyError = Class.new(Error)

        # 404 for the whole parent organization. Can be temporary, so retry on the next run.
        LocalSessionsUnavailableError = Class.new(Error)

        # 404 for one session. Routine attrition, so skip it rather than fail the run.
        SessionNotFoundError = Class.new(Error)

        PageCursorExpiredError = Class.new(Error)

        # 503 driven by the customer's settings rather than load, so it can persist.
        RetentionOverridesUnavailableError = Class.new(Error)

        RequestError = Class.new(Error)

        class BackoffError < Error
          attr_reader :retry_after

          def initialize(message, retry_after: nil, **options)
            @retry_after = retry_after

            super(message, **options)
          end
        end

        # Safe for a caller to count toward an auto-disable threshold.
        TransientError = Class.new(BackoffError)

        # 503 on a transcript page. Usually load, but under a customer-managed encryption
        # key it persists, and only recurrence tells the two apart.
        CapturedContentUnavailableError = Class.new(TransientError)

        # Deliberately not a TransientError: the budget is shared across the whole parent
        # organization, so another tool exhausting it must not disable our ingestion.
        RateLimitedError = Class.new(BackoffError)

        # `timeout` and `max_attempts` exist for callers on a web request, where the
        # retry sleeps above would hold the request open for over a minute.
        def initialize(api_key:, timeout: TIMEOUT, max_attempts: MAX_ATTEMPTS)
          raise MissingApiKeyError, 'A Compliance Access Key is required' if api_key.blank?

          @api_key = api_key
          @timeout = timeout
          @max_attempts = max_attempts
        end

        # A list cursor is re-evaluated against the retention boundary on every use, so
        # finish a walk inside 24 hours. Poll on `updated_at_gte`, not `created_at`, which
        # advances as a session's oldest calls age out.
        def local_sessions(created_at_gte: nil, created_at_lt: nil, updated_at_gte: nil, limit: nil, page: nil)
          validate_limit!(limit, MAX_SESSIONS_LIMIT)

          query = {
            'created_at.gte' => format_timestamp(created_at_gte),
            'created_at.lt' => format_timestamp(created_at_lt),
            'updated_at.gte' => format_timestamp(updated_at_gte),
            'limit' => limit,
            'page' => page
          }

          fetch_page(SESSIONS_PATH, query)
        end

        # A short page does not mean the end; keep going until `next_page` is nil.
        def local_session_messages(
          session_id, order: nil, limit: nil, page: nil,
          tool_use_input_max_bytes: nil, tool_result_max_bytes: nil)
          validate_session_id!(session_id)
          validate_limit!(limit, MAX_MESSAGES_LIMIT)
          validate_order!(order)
          validate_tool_bytes!('tool_use_input_max_bytes', tool_use_input_max_bytes)
          validate_tool_bytes!('tool_result_max_bytes', tool_result_max_bytes)

          query = {
            'order' => order,
            'limit' => limit,
            'page' => page,
            'tool_use_input_max_bytes' => tool_use_input_max_bytes,
            'tool_result_max_bytes' => tool_result_max_bytes
          }

          fetch_page("#{SESSIONS_PATH}/#{ERB::Util.url_encode(session_id)}/messages", query)
        end

        # A restarted walk begins from the first page again, so deduplicate on message `id`.
        def each_local_session_message_page(
          session_id, order: nil, limit: nil,
          tool_use_input_max_bytes: nil, tool_result_max_bytes: nil, &block)
          restarts = 0
          page = nil

          unless block
            return to_enum(
              :each_local_session_message_page, session_id,
              order: order, limit: limit,
              tool_use_input_max_bytes: tool_use_input_max_bytes,
              tool_result_max_bytes: tool_result_max_bytes
            )
          end

          MAX_PAGES.times do
            begin
              current = local_session_messages(
                session_id, page: page, order: order, limit: limit,
                tool_use_input_max_bytes: tool_use_input_max_bytes,
                tool_result_max_bytes: tool_result_max_bytes
              )
            rescue PageCursorExpiredError
              raise if restarts >= MAX_CURSOR_RESTARTS

              restarts += 1
              page = nil
              next
            end

            yield current

            previous = page
            page = current.next_page
            return if page.blank?

            raise RequestError, 'Compliance API returned a page cursor that does not advance' if page == previous
          end

          raise RequestError, "Compliance API transcript exceeded #{MAX_PAGES} pages"
        end

        private

        attr_reader :api_key, :timeout, :max_attempts

        def fetch_page(path, query)
          response = get(path, query)
          body = success_body(response)

          Page.new(
            data: Array(body['data']),
            next_page: body['next_page'],
            session: body['session'],
            rate_limit: rate_limit(response)
          )
        end

        def rate_limit(response)
          limit = response.headers['anthropic-ratelimit-requests-limit']
          return if limit.blank?

          RateLimit.new(
            limit: limit.to_i,
            remaining: response.headers['anthropic-ratelimit-requests-remaining'].to_i,
            reset_at: parse_reset_at(response.headers['anthropic-ratelimit-requests-reset'])
          )
        end

        def parse_reset_at(value)
          return if value.blank?

          Time.iso8601(value)
        rescue ArgumentError
          nil
        end

        def get(path, query)
          attempt = 0

          begin
            attempt += 1

            handle_response(perform_request(path, query))
          rescue BackoffError => e
            delay = e.retry_after || exponential_backoff(attempt)
            raise if attempt >= max_attempts || delay > MAX_BACKOFF.to_i

            sleep jittered(delay)
            retry
          end
        end

        def perform_request(path, query)
          ::Gitlab::HTTP.get(
            "#{BASE_URL}#{path}",
            query: query.compact,
            headers: headers,
            timeout: timeout,
            max_bytes: MAX_RESPONSE_SIZE
          )
        rescue *::Gitlab::HTTP::HTTP_TIMEOUT_ERRORS => e
          raise TransientError, "Compliance API request timed out (#{e.class})"
        rescue *PERMANENT_TRANSPORT_ERRORS => e
          raise RequestError, "Compliance API request failed (#{e.class})"
        rescue *::Gitlab::HTTP::HTTP_ERRORS => e
          # Never reached Anthropic, so nothing was rejected.
          raise TransientError, "Compliance API request failed (#{e.class})"
        end

        def handle_response(response)
          return response if response.success?

          code = response.code
          message = error_message(response)
          id = response.headers['request-id']
          detail = description(code, message, id)
          error_class = failure_class(code, message, response)

          if error_class <= BackoffError
            raise error_class.new(detail, request_id: id, retry_after: retry_after(response))
          end

          raise error_class.new(detail, request_id: id)
        end

        def failure_class(code, message, response)
          case code
          when 400 then message.include?(EXPIRED_CURSOR) ? PageCursorExpiredError : RequestError
          when 401, 403 then InvalidApiKeyError
          when 404 then not_found_class(message)
          when 429 then RateLimitedError
          else server_error_class(code, message, response)
          end
        end

        def not_found_class(message)
          return LocalSessionsUnavailableError if message.include?(LOCAL_SESSIONS_UNAVAILABLE)
          return SessionNotFoundError if message.include?(SESSION_NOT_FOUND)

          RequestError
        end

        def server_error_class(code, message, response)
          return RequestError if code < 500

          if code == 503
            return RetentionOverridesUnavailableError if message.include?(RETENTION_OVERRIDES_UNAVAILABLE)
            return CapturedContentUnavailableError if message.include?(CAPTURED_CONTENT_UNAVAILABLE)
          end

          retryable_server_error?(response) ? TransientError : RequestError
        end

        def success_body(response)
          body = response.parsed_response
          raise RequestError, 'Compliance API returned an unexpected body' unless body.is_a?(Hash)

          body
        rescue JSON::ParserError
          raise RequestError, 'Compliance API returned an unparsable body'
        end

        def error_message(response)
          body = response.parsed_response
          return '' unless body.is_a?(Hash)

          body.dig('error', 'message').to_s
        rescue JSON::ParserError
          ''
        end

        # A 500 with `x-should-retry: false` fails identically every time.
        def retryable_server_error?(response)
          response.headers['x-should-retry'] != 'false'
        end

        def retry_after(response)
          seconds = response.headers['retry-after'].to_i

          seconds > 0 ? seconds : nil
        end

        def exponential_backoff(attempt)
          (INITIAL_BACKOFF * (2**(attempt - 1))).to_i
        end

        # Spreads workers that failed together. Only ever waits longer, never sooner.
        def jittered(delay)
          delay + (delay * JITTER * rand)
        end

        def description(code, message, request_id)
          base = "Compliance API responded with #{code}: #{message}"

          request_id.present? ? "#{base} (request-id: #{request_id})" : base
        end

        def headers
          { 'x-api-key' => api_key }
        end

        def validate_session_id!(session_id)
          return if session_id.present?

          raise ArgumentError, 'session_id is required'
        end

        def validate_limit!(limit, maximum)
          return if limit.nil?
          return if limit.is_a?(Integer) && limit.between?(1, maximum)

          raise ArgumentError, "limit must be an integer between 1 and #{maximum}"
        end

        def validate_order!(order)
          return if order.nil? || MESSAGE_ORDERS.include?(order.to_s)

          raise ArgumentError, "order must be one of: #{MESSAGE_ORDERS.join(', ')}"
        end

        # Anthropic rejects 0 and clamps anything above its own maximum.
        def validate_tool_bytes!(name, value)
          return if value.nil? || value == TOOL_BYTES_SERVER_MAX
          return if value.is_a?(Integer) && value.between?(1, MAX_TOOL_BYTES)

          raise ArgumentError,
            "#{name} must be #{TOOL_BYTES_SERVER_MAX} or an integer between 1 and #{MAX_TOOL_BYTES}"
        end

        def format_timestamp(value)
          return if value.blank?

          parse_timestamp(value).utc.iso8601
        end

        def parse_timestamp(value)
          return parse_timestamp_string(value) if value.is_a?(String)
          return value.to_time if value.respond_to?(:to_time)

          raise ArgumentError, "timestamp must be a Time, Date, or RFC 3339 string, got #{value.class}"
        end

        def parse_timestamp_string(value)
          unless value.match?(UTC_OFFSET)
            raise ArgumentError, "timestamp #{value.inspect} must carry a UTC offset, for example 2026-07-01T00:00:00Z"
          end

          begin
            Time.iso8601(value)
          rescue ArgumentError
            raise ArgumentError, "timestamp #{value.inspect} is not a valid RFC 3339 timestamp"
          end
        end
      end
    end
  end
end
