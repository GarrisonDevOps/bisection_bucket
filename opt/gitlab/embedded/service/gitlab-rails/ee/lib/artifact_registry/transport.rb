# frozen_string_literal: true

require 'faraday'
require 'faraday/retry'

module ArtifactRegistry
  class Transport
    include Errors

    USER_AGENT = "GitLab/#{Gitlab::VERSION}".freeze
    RETRY_EXCEPTIONS = [Faraday::Retry::Middleware::DEFAULT_EXCEPTIONS, Faraday::ConnectionFailed].flatten.freeze
    # Only GET, HEAD, OPTIONS and PUT are retried. A replayed POST or PATCH could apply a write twice, and a
    # replayed DELETE 404s on a delete that already succeeded. DELETE is excluded for the whole connection,
    # so a DELETE added later is not retried by default.
    RETRY_OPTIONS = {
      max: 1,
      interval: 0,
      exceptions: RETRY_EXCEPTIONS,
      methods: (Faraday::Retry::Middleware::IDEMPOTENT_METHODS - [:delete]).freeze
    }.freeze

    JSON_CONTENT_TYPE = 'application/json'

    # Must match the `HeaderName` constant in Artifact Registry's internal/auth/servicetoken package.
    SERVICE_TOKEN_HEADER = 'Gitlab-Artifact-Registry-Token'

    BEARER_FORM = { header: 'Authorization', prefix: 'Bearer ' }.freeze
    SERVICE_TOKEN_FORM = { header: SERVICE_TOKEN_HEADER, prefix: '' }.freeze

    def initialize(base_url:, current_user:, organization:, token_exchange:, service_credential:, reporting:)
      @reporting = reporting
      validate_base_url!(base_url)

      @current_user = current_user
      @organization = organization
      @base_url = base_url
      @token_exchange = token_exchange
      @service_credential = service_credential
      @error_mapping = ErrorMapping.new(reporting)
    end

    def user_request(http_method, path, slug:, query: nil, body: nil)
      authed_request(http_method, path, form: BEARER_FORM, query: query, body: body, slug: slug) do
        raise ArgumentError, 'current_user is required for a per-user request' if @current_user.nil?

        @token_exchange.token_for(@current_user, @organization)
      end
    end

    def service_request(http_method, path, query: nil, body: nil, **attribution)
      authed_request(http_method, path, form: SERVICE_TOKEN_FORM, query: query, body: body, **attribution) do
        @service_credential.token
      end
    end

    private

    def authed_request(http_method, path, form:, query: nil, body: nil, **attribution)
      guard_transport!

      token = yield
      raise_missing_credential if token.blank?

      credential_header = { form[:header] => "#{form[:prefix]}#{token}" }

      perform_request(http_method, path, credential_header, query: query, body: body, **attribution)
    end

    def perform_request(http_method, path, credential_header, query: nil, body: nil, **attribution)
      response = connection.run_request(http_method, path, body, nil) do |req|
        req.params.update(query) if query.present?
        req.headers.update(credential_header)

        correlation_id = resolve_correlation_id
        req.headers['X-Request-Id'] = correlation_id if correlation_id.present?
      end

      handle_response(response, http_method, **attribution)
    rescue ::Faraday::Error => e
      @error_mapping.raise_transport_error(e, http_method, **attribution)
    end

    def handle_response(response, http_method, **attribution)
      status = response.status

      return response if (200..299).cover?(status)

      @error_mapping.raise_error(status, response, http_method, **attribution)
    end

    def raise_missing_credential
      raise AuthorizationError, 'No Artifact Registry credential was obtained'
    end

    def resolve_correlation_id
      Labkit::Correlation::CorrelationId.current_id
    end

    def connection
      @connection ||= Faraday.new(@base_url, headers: { user_agent: USER_AGENT },
        request: Gitlab::HTTP::DEFAULT_TIMEOUT_OPTIONS) do |conn|
        conn.options.params_encoder = Faraday::FlatParamsEncoder
        conn.request :json
        conn.response :json, content_type: JSON_CONTENT_TYPE
        conn.request :retry, RETRY_OPTIONS
        conn.request :gitlab_error_callback, error_callback_options
        conn.adapter :net_http
      end
    end

    def error_callback_options
      { callback: method(:report_attempt) }
    end

    def report_attempt(env, exception)
      @reporting.report_attempt(exception, url: attempt_url(env), method: env[:method], status: env[:status])
    end

    def attempt_url(env)
      path = env[:url]&.path
      return @base_url if path.blank?

      @reporting.redacted_snippet("#{@base_url.chomp('/')}#{path}")
    end

    def validate_base_url!(base_url)
      raise ConfigurationError, 'base_url is required' if base_url.blank?

      violation = Configuration.base_url_violation(Addressable::URI.parse(base_url.to_s))

      raise ConfigurationError, violation if violation
    rescue Addressable::URI::InvalidURIError => e
      @reporting.log_error(e, url: base_url)

      raise ConfigurationError, 'base_url is not a parseable URL'
    end

    def guard_transport!
      return unless Rails.env.production?
      return unless Addressable::URI.parse(@base_url.to_s).scheme == 'http'

      raise ConfigurationError, 'base_url must be HTTPS in production for credential-authenticated requests'
    end
  end
end
