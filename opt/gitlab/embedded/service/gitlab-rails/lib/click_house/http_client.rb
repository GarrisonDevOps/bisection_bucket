# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- existing module
  module HttpClient
    DEFAULT_OPTIONS = {
      multipart: true,
      allow_local_requests: true,
      # override default value to be always false to allow clickhouse requests in silent mode
      silent_mode_enabled: false,
      # higher timeout for test environment
      read_timeout: Rails.env.test? ? 60 : Gitlab::HTTP::DEFAULT_TIMEOUT_OPTIONS[:read_timeout]
    }.freeze

    # A select cut by timeout_overflow_mode=break can come back as HTTP 200 with
    # an empty body. For limited selects we turn it into a failure so the gem
    # raises DatabaseError, which callers already handle, not a JSON parse error.
    EMPTY_SELECT_ERROR = 'Empty response for a select limited by the %{rule} rule'
    EMPTY_SELECT_STATUS = 504

    # Lets callers tell a slow ClickHouse query from other HTTP read timeouts. It is a
    # subclass, so existing `rescue Net::ReadTimeout` and HTTP_ERRORS rescues still match.
    ReadTimeout = Class.new(Net::ReadTimeout)

    def self.build_post_proc(**additional_options)
      ->(url, headers, body) do
        options = DEFAULT_OPTIONS.merge(headers: headers, **additional_options)
        options[body.is_a?(IO) ? :body_stream : :body] = body

        rule = select_rule
        response = Gitlab::HTTP.post(with_query_settings(url, rule), options)
        build_response(response, rule)
      rescue Net::ReadTimeout => e
        raise ReadTimeout, e.io
      end
    end

    def self.select_rule
      ClickHouse::QueryLimiting.rule if ClickHouse::ReadOnlyMarker.active?
    end

    # log_comment lands in system.query_log so slow queries can be traced back to
    # the request. Settings go on the URL because CH ignores them as request
    # headers, and the URL also covers the streamed CSV insert (IO body).
    def self.with_query_settings(url, rule = select_rule)
      params = { log_comment: log_comment }

      if rule
        params.merge!(rule.settings)
        track_select(rule)
      end

      separator = url.include?('?') ? '&' : '?'

      "#{url}#{separator}#{URI.encode_www_form(params)}"
    end

    def self.build_response(response, rule = nil)
      limited = rule && rule != ClickHouse::QueryLimiting::NoLimit

      if limited && response.code == 200 && response.body.blank?
        message = format(EMPTY_SELECT_ERROR, rule: rule.type)
        return ClickHouse::Client::Response.new(message, EMPTY_SELECT_STATUS, response.headers)
      end

      ClickHouse::Client::Response.new(response.body, response.code, response.headers)
    end

    def self.track_select(rule)
      select_counter.increment(
        application: Gitlab.process_name,
        feature_category: Labkit::Context.current&.get_attribute(:feature_category) || 'unknown',
        query_limit_type: rule.type
      )
    end

    def self.select_counter
      @select_counter ||= Gitlab::Metrics.counter(
        :gitlab_click_house_select_queries_total,
        'Number of ClickHouse select queries, by the query limit rule applied'
      )
    end

    # Individual attributes are read straight off Labkit::Context rather than via
    # Gitlab::ApplicationContext.current, which materializes the whole hash and
    # forces every lazy lambda. Same tradeoff as Gitlab::QueryLogs::Tags.
    def self.log_comment
      context = Labkit::Context.current

      Gitlab::Json.dump({
        correlation_id: Labkit::Correlation::CorrelationId.current_id,
        user_id: context&.get_attribute(Labkit::Fields::GL_USER_ID),
        root_namespace_id: context&.get_attribute(Labkit::Fields::GL_ROOT_NAMESPACE_ID),
        organization_id: context&.get_attribute(:organization_id),
        application: Gitlab.process_name,
        feature_category: context&.get_attribute(:feature_category)
      }.compact)
    end
  end
end
