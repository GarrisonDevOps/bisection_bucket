# frozen_string_literal: true

module Ai
  class UsageQuotaService < BaseService
    include Gitlab::Utils::StrongMemoize

    # Used when CustomersDot sends no max-age; CustomersDot paces the TTL otherwise.
    USAGE_QUOTA_CACHE_EXPIRES_IN = 5.minutes
    MIN_CACHE_TTL = 30.seconds

    def initialize(
      user:, namespace: nil, event_type: :rails_on_ui_check,
      workflow_definition: :dap_feature_legacy, feature_ai_catalog_item: false)
      @user = user
      @namespace = namespace
      @event_type = event_type
      @workflow_definition = workflow_definition
      @feature_ai_catalog_item = feature_ai_catalog_item
    end

    def execute
      return ServiceResponse.error(message: "User is required", reason: :user_missing) unless user

      params = base_params

      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return ServiceResponse.error(message: "Namespace is required", reason: :namespace_missing) unless root_namespace
        return ServiceResponse.success if skip_quota_check_for_team_members?

        params[:root_namespace_id] = root_namespace.id
      else
        params[:unique_instance_id] = params[:instance_id] = Gitlab::GlobalAnonymousId.self_managed_instance_identifier
        params[:instance_version] = Gitlab.version_info.to_s
      end

      # To adhere to GitLab SLA we treat every error as success if it's not related to payment error
      # This also on a parity how we make this check in AIGW/DWS
      response_errors = usage_quota_response(params.compact).dig("data", "errors")

      if response_errors&.include?("402")
        ServiceResponse.error(message: "Usage quota exceeded", reason: :usage_quota_exceeded)
      elsif response_errors&.include?("403")
        ServiceResponse.error(message: "Usage billing not available", reason: :usage_billing_forbidden)
      else
        ServiceResponse.success
      end
    rescue StandardError => e
      Gitlab::AppLogger.error(
        message: 'Failed to verify usage quota',
        logging_error: "#{e.class.name}: #{e.message}",
        Labkit::Fields::GL_USER_ID => user.id
      )
      # To adhere to GitLab SLA for this specific domain we should process the request as successful
      # and not block user usage of AI Features
      ServiceResponse.success
    end

    private

    attr_reader :user, :namespace, :event_type

    def base_params
      {
        event_type: event_type,
        user_id: user.id,
        realm: ::CloudConnector.gitlab_realm,
        feature_qualified_name: feature_metadata.feature_qualified_name,
        feature_ai_catalog_item: feature_metadata.feature_ai_catalog_item
      }
    end

    def root_namespace
      user.governing_namespace(namespace&.root_ancestor)
    end
    strong_memoize_attr :root_namespace

    def skip_quota_check_for_team_members?
      user.gitlab_team_member? &&
        Feature.disabled?(:enable_quota_check_for_team_members, user) &&
        !Gitlab::AiGateway.internal_ai_usage?(root_namespace.id)
    end

    def skip_cache?
      Rails.env.development? && Feature.enabled?(:use_mock_dot_api_for_usage_quota, :instance)
    end

    def plan_key
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        root_namespace.actual_plan_name
      else
        License.current&.trial?.to_s
      end
    end

    def cache_key(params)
      params_string = params.merge(plan_key: plan_key).sort.to_s
      "usage_quota_dot_query:#{Digest::SHA256.hexdigest(params_string)}"
    end

    def feature_metadata
      return legacy_feature_metadata if legacy_workflow_definition?

      workflow_feature_metadata
    end

    def legacy_workflow_definition?
      @workflow_definition.nil? || @workflow_definition.to_s == 'dap_feature_legacy'
    end

    def legacy_feature_metadata
      ::Gitlab::SubscriptionPortal::FeatureMetadata.for(:dap_feature_legacy)
    end

    def workflow_feature_metadata
      ::Gitlab::SubscriptionPortal::FeatureMetadata::Feature.new(
        feature_qualified_name: @workflow_definition,
        feature_ai_catalog_item: @feature_ai_catalog_item
      )
    end

    def usage_quota_response(params)
      return ::Gitlab::SubscriptionPortal::Client.verify_usage_quota(params) if skip_cache?

      key = cache_key(params)
      cached = Rails.cache.read(key)
      return cached if cached

      response = ::Gitlab::SubscriptionPortal::Client.verify_usage_quota(params)
      ttl = [response[:cache_ttl] || USAGE_QUOTA_CACHE_EXPIRES_IN, MIN_CACHE_TTL].max
      Rails.cache.write(key, response, expires_in: ttl)
      response
    end
  end
end
