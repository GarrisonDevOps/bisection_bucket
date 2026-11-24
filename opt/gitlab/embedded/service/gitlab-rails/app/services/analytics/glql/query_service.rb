# frozen_string_literal: true

module Analytics
  module Glql
    # Service for handling GLQL queries with rate limiting, complexity tracking, and logging
    # Used by both Glql::BaseController and API::Glql
    class QueryService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::Loggable

      GlqlQueryLockedError = Class.new(StandardError)

      # Raised when a DB-time budget is spent.
      class GlqlBudgetExceededError < GlqlQueryLockedError
        # @return [Integer] seconds the caller should wait before retrying
        attr_reader :retry_after

        def initialize(message, retry_after:)
          super(message)
          @retry_after = retry_after
        end
      end

      # ClickHouse answers a server-side max_execution_time hit with HTTP 408 and a body starting
      # with its error code, which the gem raises as a DatabaseError.
      module ClickHouseTimeoutExceeded
        # @param error [Exception]
        # @return [Boolean]
        def self.===(error)
          error.is_a?(::ClickHouse::Client::DatabaseError) && error.message.start_with?('Code: 159.')
        end
      end
      private_constant :ClickHouseTimeoutExceeded

      TIMEOUT_ERRORS = [
        ActiveRecord::QueryAborted,
        ::ClickHouse::HttpClient::ReadTimeout,
        ClickHouseTimeoutExceeded
      ].freeze
      private_constant :TIMEOUT_ERRORS

      def initialize(current_user:, original_query:, request: nil, current_organization: nil)
        @current_user = current_user
        @original_query = original_query
        @request = request
        @current_organization = current_organization
      end

      def execute(query:, variables: {}, context: {}, operation_name: nil)
        @query = query
        @variables = variables
        @operation_name = operation_name
        @graphql_context = build_graphql_context(context)

        start_time = Gitlab::Metrics::System.monotonic_time
        exception_caught = nil

        begin
          check_rate_limit
          result = execute_graphql

          # Enhance GraphQL logs with GLQL metadata for both controller and API
          enhance_graphql_logs

          query_result = build_result(
            start_time,
            data: result&.dig('data'),
            errors: normalize_errors(result&.dig('errors'))
          )

          # Log execution metrics for monitoring and optimization
          log_execution_metrics(query_result)

          query_result

        rescue GlqlQueryLockedError => e
          exception_caught = e
          # Enhance logs even for rate limited queries
          enhance_graphql_logs

          build_result(start_time, errors: [{ message: e.message }], complexity_score: nil, rate_limited: true)
            .merge(retry_after: e.is_a?(GlqlBudgetExceededError) ? e.retry_after : nil)

        rescue *timeout_errors => e
          exception_caught = e
          # Handle timeout - increment rate limiter
          increment_rate_limit_counter

          # Enhance logs for timeout scenarios
          enhance_graphql_logs

          query_result = build_result(start_time, errors: [{ message: 'Query timed out' }], timeout_occurred: true)

          # Log execution metrics for monitoring and optimization
          log_execution_metrics(query_result)

          query_result

        rescue StandardError => e
          exception_caught = e
          # Handle other errors
          enhance_graphql_logs

          build_result(start_time, errors: [{ message: e.message }]).merge(exception: e)

        ensure
          # A throttled query never ran, so it would only count as a fast success.
          unless exception_caught.is_a?(GlqlQueryLockedError)
            increment_glql_sli(
              duration_s: Gitlab::Metrics::System.monotonic_time - start_time,
              error_type: error_type_from(exception_caught)
            )
          end

          db_time_budget.charge!
        end
      end

      private

      attr_reader :current_user, :original_query, :request, :current_organization, :query, :variables,
        :graphql_context, :operation_name

      def check_rate_limit
        if Gitlab::ApplicationRateLimiter.peek(:glql, scope: { query_sha: query_sha })
          raise GlqlQueryLockedError,
            'Query temporarily blocked due to repeated timeouts. Please try again later or narrow your search scope.'
        end

        check_db_time_budget
      end

      def check_db_time_budget
        exceeded_keys = db_time_budget.exceeded_keys
        return if exceeded_keys.empty?

        enforced = Feature.enabled?(:enforce_glql_db_time_budgets, current_user)

        Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            message: 'GLQL DB-time budget exceeded',
            glql_query_sha: query_sha,
            glql_budget_keys: exceeded_keys.map(&:to_s),
            glql_budget_enforced: enforced
          )
        )

        return unless enforced

        raise GlqlBudgetExceededError.new(
          Gitlab::ApplicationRateLimiter.throttled_error_message,
          retry_after: exceeded_keys.map { |key| Gitlab::ApplicationRateLimiter.period_for(key) }.max
        )
      end

      def db_time_budget
        DbTimeBudget.new(current_user: current_user, query_sha: query_sha, request: request)
      end
      strong_memoize_attr :db_time_budget

      def execute_graphql
        ::Gitlab::Database::LoadBalancing::SessionMap.use_replica_if_available do
          GitlabSchema.execute(query, variables: variables, context: graphql_context, operation_name: operation_name)
        end
      end

      def build_result(
        start_time, errors:, data: nil, complexity_score: extract_complexity_score, timeout_occurred: false,
        rate_limited: false)
        {
          data: data,
          errors: errors,
          complexity_score: complexity_score,
          duration_s: Gitlab::Metrics::System.monotonic_time - start_time,
          timeout_occurred: timeout_occurred,
          rate_limited: rate_limited
        }
      end

      def build_graphql_context(additional_context = {})
        base_context = {
          current_user: current_user,
          is_sessionless_user: true,
          current_organization: current_organization,
          request: request
        }

        base_context.merge(additional_context)
      end

      def extract_complexity_score
        graphql_logs = RequestStore.store[:graphql_logs]
        return unless graphql_logs&.any?

        graphql_logs.last&.dig(:complexity)
      end

      def enhance_graphql_logs
        # Add GLQL-specific metadata to GraphQL logs
        # This ensures both controller and API have consistent log format
        graphql_logs = RequestStore.store[:graphql_logs]
        return unless graphql_logs&.any?

        RequestStore.store[:graphql_logs] = graphql_logs.map do |log|
          log.merge(
            glql_referer: request&.headers&.[]("Referer"),
            glql_query_sha: query_sha
          )
        end
      end

      def query_sha
        Digest::SHA256.hexdigest(original_query)
      end

      strong_memoize_attr :query_sha

      def increment_rate_limit_counter
        Gitlab::ApplicationRateLimiter.throttled?(:glql, scope: { query_sha: query_sha })
      end

      def increment_glql_sli(duration_s:, error_type:)
        labels = Gitlab::Metrics::GlqlSlis.labels(
          endpoint_id: caller_endpoint_id,
          error_type: error_type,
          duo_agent: duo_agent_request?
        )

        Gitlab::Metrics::GlqlSlis.record_error(labels: labels, error: error_type.present?)

        return if error_type

        Gitlab::Metrics::GlqlSlis.record_apdex(
          labels: labels,
          success: duration_s <= Gitlab::Metrics::GlqlSlis.query_urgency.duration
        )
      end

      def caller_endpoint_id
        # Try to get from ApplicationContext, fallback to generic
        ::Gitlab::ApplicationContext.current_context_attribute(:caller_id) || 'Glql::QueryService'
      end

      # Workhorse sends X-Gitlab-Duo-Workflow-Id with Duo Agent Platform tool calls, but any client can
      # send it, so this classifies traffic for metrics only and must not gate behaviour.
      def duo_agent_request?
        ::Gitlab::ApplicationContext.current_context_attribute(:duo_workflow_id).present?
      end

      def log_execution_metrics(result)
        # Use LoggingService for consistent logging across API and Controller
        # Note: GLQL-specific details (glql_query, generated_graphql) are not available here
        # and should be added by the caller (API) if needed
        LoggingService.new(
          current_user: current_user,
          result: result,
          query_sha: query_sha
        ).execute
      end

      # @param exception [Exception, nil]
      # @return [Symbol, nil]
      def error_type_from(exception)
        return unless exception

        case exception
        when *timeout_errors then :query_aborted
        else :other
        end
      end

      # @return [Array<Module>] errors that mean the query ran too long, so the circuit breaker counts them
      def timeout_errors
        TIMEOUT_ERRORS
      end

      # Normalize GraphQL errors to use symbol keys consistently. `extensions` carries
      # machine-readable error codes the frontend maps to panel states, so it survives.
      def normalize_errors(errors)
        return unless errors

        errors.map do |error|
          next error unless error.is_a?(Hash) && error.key?("message")

          { message: error["message"], extensions: error["extensions"] }.compact
        end
      end
    end
  end
end

Analytics::Glql::QueryService.prepend_mod
