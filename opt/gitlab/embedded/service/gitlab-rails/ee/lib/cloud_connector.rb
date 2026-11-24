# frozen_string_literal: true

module CloudConnector
  extend self

  GITLAB_REALM_COM = '.com'
  GITLAB_REALM_SAAS = 'saas'
  GITLAB_REALM_SELF_MANAGED = 'self-managed'
  GITLAB_REALM_DEDICATED = 'dedicated'

  def gitlab_realm
    gitlab_realm_saas? ? GITLAB_REALM_SAAS : GITLAB_REALM_SELF_MANAGED
  end

  def deployment_type
    return GITLAB_REALM_DEDICATED if ::Gitlab::Dedicated.feature_available?(:cloud_connector_on_dedicated)

    gitlab_realm_saas? ? GITLAB_REALM_COM : GITLAB_REALM_SELF_MANAGED
  end

  def headers(user)
    {
      'x-gitlab-host-name' => Gitlab.config.gitlab.host,
      'x-gitlab-instance-id' => Gitlab::GlobalAnonymousId.instance_id,
      'x-gitlab-realm' => ::CloudConnector.gitlab_realm,
      'x-gitlab-deployment-type' => ::CloudConnector.deployment_type,
      'x-gitlab-version' => Gitlab.version_info.to_s
    }.tap do |result|
      result['x-gitlab-global-user-id'] = Gitlab::GlobalAnonymousId.user_id(user) if user
      result['x-gitlab-user-id'] = user.id.to_s if user
    end
  end

  ###
  # Returns required HTTP header fields when making AI requests through Cloud Connector.
  #
  #  user - User making the request, may be null.
  #  namespace_ids - Root namespace IDs for which Duo features are available.
  #                  This should only be set when the request is made on gitlab.com.
  def ai_headers(user, namespace_ids: [], subject: user)
    headers(user).merge(
      'x-gitlab-feature-enabled-by-namespace-ids' => namespace_ids.join(','),
      'x-gitlab-subject-type' => subject&.user_type.to_s
    )
  end

  def gitlab_realm_saas?
    Gitlab.org_or_com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- Will be addressed in https://gitlab.com/gitlab-org/gitlab/-/issues/437725
  end

  def self_managed_cloud_connected?
    !gitlab_realm_saas? && !::Gitlab::AiGateway.self_hosted_url.present?
  end
end
