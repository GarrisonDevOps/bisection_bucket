# frozen_string_literal: true

class JiraConnect::EventsController < JiraConnect::ApplicationController
  # See https://developer.atlassian.com/cloud/jira/software/app-descriptor/#lifecycle

  skip_before_action :verify_atlassian_jwt!
  before_action :verify_asymmetric_atlassian_jwt!

  def installed
    if jira_connect_domain_not_allowed?
      log_lifecycle_failure(action: :installed, errors: ['Jira domain is not allowlisted'])
      return head :unprocessable_entity
    end

    installation = current_jira_installation || native_installation
    success = installation ? update_installation(installation) : create_installation

    if success
      head :ok
    else
      head :unprocessable_entity
    end
  end

  def uninstalled
    # The Forge preUninstall hook may have destroyed the row first.
    unless current_jira_installation
      log_lifecycle_failure(action: :uninstall, errors: ['Installation not found'])
      return head :ok
    end

    if JiraConnectInstallations::DestroyService.execute(
      current_jira_installation,
      jira_connect_base_path,
      jira_connect_events_uninstalled_path
    )
      head :ok
    else
      log_lifecycle_failure(action: :uninstall, errors: current_jira_installation&.errors&.full_messages)
      head :unprocessable_entity
    end
  end

  private

  def create_installation
    installation = JiraConnectInstallation.new(create_params)
    return true if installation.save

    log_lifecycle_failure(action: :create, errors: installation.errors.full_messages)
    false
  end

  def native_installation
    JiraConnectInstallation.find_native_by_cloud_id(
      cloud_id: transformed_params[:cloud_id], organization_id: Current.organization.id
    )
  end

  def update_installation(installation)
    # An adopted native row has no client key yet.
    attributes = installation.client_key? ? update_params : create_params
    response = JiraConnectInstallations::UpdateService.execute(
      installation,
      nil,
      attributes,
      skip_jira_admin_check: true
    )
    return true if response.success?

    log_lifecycle_failure(action: :update, errors: extract_errors(response.message))
    false
  end

  def extract_errors(message)
    return message.full_messages if message.respond_to?(:full_messages)

    Array.wrap(message)
  end

  def log_lifecycle_failure(action:, errors:)
    Gitlab::IntegrationsLogger.info(
      integration: 'JiraConnect',
      message: 'JiraConnect lifecycle event rejected',
      jira_event_action: action,
      jira_client_key: transformed_params[:client_key],
      jira_errors: errors
    )
  end

  def jira_connect_domain_not_allowed?
    allowlist = Gitlab::CurrentSettings.jira_connect_domain_allowlist
    return false if allowlist.empty?

    allowlist.exclude?(jira_connect_base_url_host)
  end

  def jira_connect_base_url_host
    base_url = transformed_params[:base_url]
    return '' if base_url.blank?

    URI(base_url).host.to_s.downcase
  rescue URI::InvalidURIError
    ''
  end

  def create_params
    transformed_params
      .permit(:client_key, :shared_secret, :base_url, :display_url, :cloud_id)
      .merge(organization_id: Current.organization.id)
  end

  def update_params
    transformed_params
      .permit(:shared_secret, :base_url, :display_url, :cloud_id)
      .merge(organization_id: Current.organization.id)
  end

  def transformed_params
    @transformed_params ||= params
      .permit(:clientKey, :sharedSecret, :baseUrl, :displayUrl, :cloudId)
      .transform_keys(&:underscore)
  end

  def verify_asymmetric_atlassian_jwt!
    token = auth_token
    return head :unauthorized unless valid_token_size?(token)

    asymmetric_jwt = Atlassian::JiraConnect::Jwt::Asymmetric.new(
      token,
      jwt_verification_claims,
      base_url: transformed_params[:base_url]
    )
    return head :unauthorized unless asymmetric_jwt.valid?

    @current_jira_installation = JiraConnectInstallation.find_by_client_key_and_organization_id(
      asymmetric_jwt.iss_claim,
      Current.organization.id
    )
  end

  def jwt_verification_claims
    {
      aud: calculate_audiences,
      iss: transformed_params[:client_key],
      qsh: Atlassian::Jwt.create_query_string_hash(request.url, request.method, jira_connect_base_url)
    }
  end

  def calculate_audiences
    audiences = if Gitlab.config.jira_connect.enforce_jira_base_url_https
                  [jira_connect_base_url(protocol: 'https')]
                else
                  [jira_connect_base_url]
                end

    if (additional_url = Gitlab::CurrentSettings.jira_connect_additional_audience_url).present?
      audiences << Gitlab::Utils.append_path(additional_url, "-/jira_connect")
    end

    audiences
  end
end
