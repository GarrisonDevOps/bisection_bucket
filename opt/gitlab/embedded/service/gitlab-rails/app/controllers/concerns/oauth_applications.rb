# frozen_string_literal: true

module OauthApplications
  extend ActiveSupport::Concern
  include Gitlab::Utils::StrongMemoize

  CREATED_SESSION_KEY = :oauth_applications_created
  GRANULAR_SCOPE_PARAMS = [:access, { permissions: [], resource_ids: [] }].freeze

  included do
    before_action :prepare_scopes, only: [:create, :update]

    helper_method :granular_scope_inputs
  end

  def prepare_scopes
    scopes = params.permit(authn_oauth_application: { scopes: [] }).dig(:authn_oauth_application, :scopes)

    # Written back in place because Doorkeeper expects a single space-separated
    # string, while the form submits one checkbox value per scope.
    params.require(:authn_oauth_application)[:scopes] = scopes.join(' ') if scopes
  end

  def set_created_session
    session[CREATED_SESSION_KEY] = true
  end

  def get_created_session
    session.delete(CREATED_SESSION_KEY) || false
  end

  def load_scopes
    @scopes ||= Doorkeeper::OAuth::Scopes.from_array(
      Doorkeeper.configuration.scopes.to_a - excluded_scopes
    )
  end

  def permitted_params
    %i[name redirect_uri scopes confidential device_code_enabled]
  end

  protected

  def excluded_scopes
    [
      ::Gitlab::Auth::AI_WORKFLOW.to_s,
      ::Gitlab::Auth::DYNAMIC_USER.to_s,
      ::Gitlab::Auth::SELF_ROTATE_SCOPE.to_s,
      ::Gitlab::Auth::GRANULAR_SCOPE.to_s
    ]
  end

  def application_params
    params
      .require(:authn_oauth_application)
      .permit(*permitted_params)
  end

  def application_params_with_granular_scopes
    inputs = granular_scope_inputs
    return application_params if inputs.nil?

    application_params.to_h.merge(granular_scopes: inputs)
  end

  def granular_scope_inputs
    return unless Feature.enabled?(:granular_oauth_tokens, current_user)

    scopes = params.permit(authn_oauth_application: { granular_scopes: GRANULAR_SCOPE_PARAMS })
      .dig(:authn_oauth_application, :granular_scopes)
    return if scopes.blank?

    # Posted as granular_scopes[0][...] because Rack cannot tell which element a
    # granular_scopes[][permissions][] value belongs to, so they arrive keyed by index
    scopes = scopes.to_h.values if scopes.respond_to?(:keys)

    Array(scopes).map { |scope| builder_input_for(scope.to_h.symbolize_keys) }
  end
  strong_memoize_attr :granular_scope_inputs

  def builder_input_for(scope)
    ids_by_model = Array(scope[:resource_ids]).filter_map { |id| GlobalID.parse(id) }.group_by(&:model_name)

    {
      access: scope[:access].to_s.downcase,
      permissions: Array(scope[:permissions]),
      group_ids: ids_by_model.fetch(::Group.name, []).map(&:model_id),
      project_ids: ids_by_model.fetch(::Project.name, []).map(&:model_id)
    }
  end
end
