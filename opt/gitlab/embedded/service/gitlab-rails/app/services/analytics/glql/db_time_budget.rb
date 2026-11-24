# frozen_string_literal: true

module Analytics
  module Glql
    # Budgets the database time (every database, primaries and replicas) that GLQL
    # requests use, per query text and per caller (the user, or the IP address for
    # guests), in the windows set by the glql_db_seconds_* rate limits. A user's
    # Duo Agent Platform flows have their own budget, separate from the user's.
    #
    # Time is charged after each request, so a spent budget blocks the requests
    # that follow, not the one that spent it. The charge is the whole request's
    # database time, which includes small queries such as authentication.
    class DbTimeBudget
      include Gitlab::Utils::StrongMemoize

      # @param current_user [User, nil]
      # @param query_sha [String] SHA256 of the GLQL query text
      # @param request [ActionDispatch::Request, Grape::Request, nil]
      def initialize(current_user:, query_sha:, request:)
        @current_user = current_user
        @query_sha = query_sha
        @request = request
      end

      # Returns the rate-limit keys whose budget is spent, without charging them.
      #
      # @return [Array<Symbol>]
      def exceeded_keys
        scopes.filter_map do |key, scope|
          key if ::Gitlab::ApplicationRateLimiter.peek(key, scope: scope)
        end
      end

      # Charges the database time this request has used, on every database, to every budget.
      #
      # @return [void]
      def charge!
        keys = ::Gitlab::Metrics::Subscribers::ActiveRecord.load_balancing_metric_query_duration_keys
        cost = keys.sum { |key| ::Gitlab::SafeRequestStore[key].to_f }
        return if cost <= 0

        scopes.each do |key, scope|
          ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope, cost: cost)
        end

        nil
      end

      private

      attr_reader :current_user, :query_sha, :request

      def scopes
        { glql_db_seconds_by_query_sha: { query_sha: query_sha } }.merge(caller_scope)
      end
      strong_memoize_attr :scopes

      def caller_scope
        # Authentication has already swapped a composite identity, such as a Duo service account,
        # for the user it acts for, so that user is charged.
        if current_user
          { user_key => { user: current_user } }
        elsif request&.ip
          { glql_db_seconds_by_ip: { ip: request.ip } }
        else
          {}
        end
      end

      def user_key
        duo_flow_token? ? :glql_duo_db_seconds_by_user : :glql_db_seconds_by_user
      end

      # Only tokens minted for Duo Agent Platform flows carry the ai_workflows
      # scope: personal access tokens can't be given it.
      def duo_flow_token?
        Array(::Current.token_info&.dig(:token_scopes)).include?(::Gitlab::Auth::AI_WORKFLOW)
      end
    end
  end
end
