# frozen_string_literal: true

module Gitlab
  module AiGateway
    ForbiddenError = Class.new(StandardError)
    ClientError = Class.new(StandardError)
    # The AI Gateway, or a proxy in front of it, rejected the request body as too large (HTTP 413).
    RequestTooLargeError = Class.new(ClientError)
    ServerError = Class.new(StandardError)
    NoCloudConnectorTokenError = Class.new(::Gitlab::Llm::AiGateway::Client::ConnectionError)

    FEATURE_FLAG_CACHE_KEY = "gitlab_ai_gateway_feature_flags"
    CURRENT_CONTEXT_CACHE_KEY = "gitlab_ai_gateway_current_context"
    ACCESS_TOKEN_PATH = "/v1/code/user_access_token"

    CONTEXT_KEY_TO_HEADER = {
      x_gitlab_client_type: 'X-Gitlab-Client-Type',
      x_gitlab_client_version: 'X-Gitlab-Client-Version',
      x_gitlab_client_name: 'X-Gitlab-Client-Name',
      x_gitlab_interface: 'X-Gitlab-Interface',
      x_gitlab_tracking_context: 'X-Gitlab-Tracking-Context'
    }.freeze

    def self.url
      self_hosted_url || cloud_connector_url
    end

    def self.cloud_connector_url
      development_url || "#{::CloudConnector::Config.base_url}/ai"
    end

    def self.cloud_connector_auth_url
      development_url || "#{::CloudConnector::Config.base_url}/auth"
    end

    def self.access_token_url(code_completions_feature_setting)
      base_url = if code_completions_feature_setting&.vendored?
                   cloud_connector_auth_url
                 else
                   self_hosted_url || cloud_connector_auth_url
                 end

      "#{base_url}#{ACCESS_TOKEN_PATH}"
    end

    def self.self_hosted_url
      ::Gitlab::CurrentSettings.ai_gateway_url&.chomp('/')
    end

    def self.development_url
      ENV["DEVELOPMENT_AI_GATEWAY_URL"]&.chomp('/')
    end

    def self.has_self_hosted_ai_gateway?
      !self_hosted_url.blank?
    end

    # An offline cloud license is never issued a cloud connector access token, so a request
    # routed to the cloud connector, by a vendored feature setting or an unset AI Gateway URL,
    # reaches that host with no credential it issued.
    def self.no_cloud_connector_token?(feature_setting, vendored: false)
      return false unless ::License.current&.offline_cloud_license?
      return false if development_url.present?

      vendored || feature_setting&.vendored? || !has_self_hosted_ai_gateway?
    end

    def self.request_url!(feature_setting = nil, vendored: false, title: nil)
      raise ArgumentError, 'title: is required with vendored: true' if vendored && title.blank?

      ensure_cloud_connector_token!(feature_setting, vendored: vendored, title: title)

      vendored ? cloud_connector_url : (feature_setting&.base_url || url)
    end

    def self.access_token_url!(code_completions_feature_setting, title: nil)
      ensure_cloud_connector_token!(code_completions_feature_setting, vendored: false, title: title)

      access_token_url(code_completions_feature_setting)
    end

    def self.enabled_instance_verbose_ai_logs
      ::Gitlab::CurrentSettings.enabled_instance_verbose_ai_logs.to_s
    end

    def self.timeout
      ::Gitlab::CurrentSettings.ai_gateway_timeout_seconds&.seconds || 120.seconds
    end

    # Exposes the state of a feature flag to the AI Gateway code.
    #
    # name - The name of the feature flag, e.g. `my_feature`.
    # args - Any additional arguments to pass to `Feature.enabled?`. This allows
    #        you to check if a flag is enabled for a particular user.
    def self.push_feature_flag(name, *args, **kwargs)
      enabled = Feature.enabled?(name, *args, **kwargs)

      return unless enabled

      # We don't want the `expanded_ai_logging` feature flag to be pushed to AIGW
      # on any kind of self-managed instance (including instances running Self-hosted Duo)
      # Expanded logging will work via `enabled_instance_verbose_ai_logs` for self-hosted Duo
      # And, expanded logging should not work at all for self-managed instances connected to cloud AIGW.
      # Essentially, `expanded_ai_logging` FF should only work on gitlab.com, for
      # debugging purposes.
      return if expanded_ai_logging_on_self_managed?(name)

      enabled_feature_flags.append(name)
    end

    def self.current_context
      Gitlab::SafeRequestStore.fetch(CURRENT_CONTEXT_CACHE_KEY) { {} }
    end

    # Appended feature flags to the current context.
    # We use SafeRequestStore for the context management which refresh the cache per API request or Sidekiq job run.
    # See https://gitlab.com/gitlab-org/gitlab/-/blob/master/gems/gitlab-safe_request_store/README.md
    def self.enabled_feature_flags
      Gitlab::SafeRequestStore.fetch(FEATURE_FLAG_CACHE_KEY) { [] }
    end

    def self.expanded_ai_logging_on_self_managed?(name)
      # gitlab_com_subscriptions is only available on GitLab.com (SaaS)
      # so its absence indicates a self-managed instance
      self_managed_instance = !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      name.to_sym == :expanded_ai_logging && self_managed_instance
    end

    # rubocop:disable Metrics/ParameterLists -- all arguments are needed
    def self.headers(
      user:, unit_primitive_name:, ai_feature_name: unit_primitive_name, namespace_id: nil, governing_namespace_id: nil,
      agent: nil, lsp_version: nil, project_id: nil, organization_id: nil, feature_setting: nil, extra_claims: {},
      bearer_token: nil
    )
      # Normalize to Symbol; callers may pass either.
      unit_primitive_name = unit_primitive_name.to_sym
      ai_feature_name = ai_feature_name.to_sym

      auth_response = resolve_auth_response(
        user: user,
        ai_feature_name: ai_feature_name,
        unit_primitive_name: unit_primitive_name)

      bearer_token ||= cloud_connector_token(
        unit_primitive_name,
        user,
        feature_setting: feature_setting,
        root_namespace_id: governing_namespace_id,
        enablement_type: enablement_type_for(auth_response),
        extra_claims: extra_claims)

      {
        'X-Gitlab-Authentication-Type' => 'oidc',
        'Authorization' => "Bearer #{bearer_token}",
        'Content-Type' => 'application/json',
        'X-Request-ID' => Labkit::Correlation::CorrelationId.current_or_new_id,
        # Forward the request time to the model gateway to calculate latency
        'X-Gitlab-Rails-Send-Start' => Time.now.to_f.to_s
      }.merge(public_headers(user: user, ai_feature_name: ai_feature_name, unit_primitive_name: unit_primitive_name,
        namespace_id: namespace_id, governing_namespace_id: governing_namespace_id,
        project_id: project_id, organization_id: organization_id, auth_response: auth_response))
        .tap do |result|
          result['User-Agent'] = agent if agent
          result.merge!(forwarded_headers)

          # Forward the X-Gitlab-Language-Server-Version on to the model gateway
          result['X-Gitlab-Language-Server-Version'] = lsp_version if lsp_version

          # Pass the distributed tracing LangSmith header to AI Gateway.
          result.merge!(Langsmith::RunHelpers.to_headers) if Langsmith::RunHelpers.enabled?
        end
    end
    # rubocop:enable Metrics/ParameterLists

    def self.add_namespace_headers!(headers, namespace_id, billable_namespace_id)
      return unless billable_namespace_id

      headers['x-gitlab-namespace-id'] = (namespace_id || billable_namespace_id).to_s
      headers['x-gitlab-root-namespace-id'] = billable_namespace_id.to_s
    end

    def self.add_organization_header!(headers, organization_id)
      return unless organization_id

      headers['x-gitlab-organization-id'] = organization_id.to_s
    end

    def self.public_headers( # rubocop:disable Metrics/ParameterLists -- subject is a distinct identity from user (billing attribution) and must stay separate from the permission/token args
      user:,
      ai_feature_name:,
      unit_primitive_name:,
      namespace_id: nil,
      project_id: nil,
      organization_id: nil,
      governing_namespace_id: nil,
      feature_setting: nil,
      subject: user,
      auth_response: nil
    )
      auth_response ||= resolve_auth_response(
        user: user,
        ai_feature_name: ai_feature_name,
        unit_primitive_name: unit_primitive_name,
        feature_setting: feature_setting)
      enablement_type = enablement_type_for(auth_response)
      namespace_ids = auth_response&.namespace_ids || []
      root_namespace_ids = Namespace.root_ids_for(namespace_ids)
      feature_flags = enabled_feature_flags.uniq
      feature_flags << :internal_ai_usage if internal_ai_usage?(governing_namespace_id)

      ::CloudConnector.ai_headers(user, namespace_ids: root_namespace_ids, subject: subject).merge(
        'x-gitlab-feature-enablement-type' => enablement_type,
        'x-gitlab-unit-primitive' => unit_primitive_name.to_s,
        'x-gitlab-enabled-feature-flags' => feature_flags.join(','),
        'x-gitlab-enabled-instance-verbose-ai-logs' => enabled_instance_verbose_ai_logs,
        'X-Gitlab-Is-Team-Member' => gitlab_team_member?(user).to_s
      ).tap do |result|
        add_namespace_headers!(result, namespace_id, governing_namespace_id)
        add_organization_header!(result, organization_id)
        result['x-gitlab-project-id'] = project_id.to_s if project_id.presence
      end
    end

    def self.resolve_auth_response(user:, ai_feature_name:, unit_primitive_name:, feature_setting: nil)
      user&.allowed_to_use(ai_feature_name, unit_primitive_name: unit_primitive_name,
        feature_setting: feature_setting)
    end

    def self.enablement_type_for(auth_response)
      auth_response&.enablement_type || ''
    end

    def self.cloud_connector_token(
      unit_primitive_name, user, enablement_type:, feature_setting: nil, root_namespace_id: nil,
      extra_claims: {})
      team_member = gitlab_team_member?(user)

      claims = {}
      claims[:gitlab_team_member] = team_member
      claims[:skip_usage_cutoff] = team_member && !internal_ai_usage?(root_namespace_id)

      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && root_namespace_id
        claims[:gitlab_root_namespace_id] = root_namespace_id
      end

      # Signed even when empty. An absent claim and an empty one mean different
      # things downstream, so a user with no resolved type still gets a value.
      claims[:feature_enablement_type] = enablement_type

      # Until https://gitlab.com/groups/gitlab-org/-/epics/15639 is complete, we generate service
      # definitions for each UP, so passing the service name here should be safe, even if `service`
      # is not defined explicitly.
      ::CloudConnector::Tokens.get(
        unit_primitive: unit_primitive_name,
        resource: user,
        feature_setting: feature_setting,
        extra_claims: extra_claims.merge(claims)
      )
    end

    def self.internal_ai_usage?(root_namespace_id)
      return false unless root_namespace_id && ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      Feature.enabled?(:internal_ai_usage, Group.actor_from_id(root_namespace_id))
    end

    private_class_method def self.ensure_cloud_connector_token!(feature_setting, vendored:, title:)
      return unless no_cloud_connector_token?(feature_setting, vendored: vendored)

      raise NoCloudConnectorTokenError,
        no_cloud_connector_token_message(feature_setting, vendored: vendored,
          title: title.presence || feature_setting&.title)
    end

    private_class_method def self.no_cloud_connector_token_message(feature_setting, vendored:, title:)
      needs_url = !has_self_hosted_ai_gateway?
      needs_model = vendored || !!feature_setting&.vendored?

      if needs_url && needs_model
        format(s_('AiPowered|An offline cloud license is not issued a cloud connector access token, so this ' \
          'request would reach the cloud connector without one. Set the "Local AI Gateway URL" and assign a ' \
          'self-hosted model to the "%{title}" feature settings in your GitLab Duo settings'), title: title)
      elsif needs_url
        s_('AiPowered|An offline cloud license is not issued a cloud connector access token, so this request ' \
          'would reach the cloud connector without one. Set the "Local AI Gateway URL" in your GitLab Duo settings')
      else
        format(s_('AiPowered|An offline cloud license is not issued a cloud connector access token, so this ' \
          'request would reach the cloud connector without one. Assign a self-hosted model to the "%{title}" ' \
          'feature settings in your GitLab Duo settings'), title: title)
      end
    end

    private_class_method def self.forwarded_headers
      ctx = current_context
      CONTEXT_KEY_TO_HEADER.filter_map { |key, header| [header, ctx[key]] if ctx[key] }.to_h
    end

    private_class_method def self.gitlab_team_member?(user)
      !!::Gitlab::Tracking::StandardContext.new.gitlab_team_member?(user&.id)
    end
  end
end
