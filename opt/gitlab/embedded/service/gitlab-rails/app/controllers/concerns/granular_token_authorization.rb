# frozen_string_literal: true

module GranularTokenAuthorization
  extend ActiveSupport::Concern
  include Gitlab::Utils::StrongMemoize

  # Default granular permission per sessionless format; formats absent here are not enforced.
  GRANULAR_FORMAT_PERMISSIONS = {
    rss: :read_work_item,
    ics: :read_work_item,
    archive: :download_code,
    download: :read_release,
    design: :read_design,
    editor_extension: :create_editor_telemetry
  }.freeze

  # Formats that return the same data to every reader (a repository archive, a release link download),
  # so a token that only the public access rule admits gets what anonymous users get. Only with the
  # format's default permission: a `permission:` override can name a read that depends on the reader.
  GRANULAR_PUBLIC_ACCESS_FORMATS = %i[archive download].freeze

  def authorize_granular_token!(request_format, permission: nil)
    permission ||= GRANULAR_FORMAT_PERMISSIONS[request_format]
    return unless permission

    token = sessionless_access_token
    return unless token

    allow_public_access = GRANULAR_PUBLIC_ACCESS_FORMATS.include?(request_format) &&
      permission == GRANULAR_FORMAT_PERMISSIONS[request_format]
    return if granular_scopes_authorized?(token, permission, granular_token_boundary, allow_public_access:)

    deny_granular_token!
  end

  private

  # `Current.token_info` is set by the auth finders on success; nil for sessions,
  # feed tokens, and invalid tokens.
  def sessionless_access_token
    info = ::Current.token_info
    return unless info

    case info[:token_type]
    when ::PersonalAccessToken.name
      ::PersonalAccessToken.find_by_id(info[:token_id])
    when ::OauthAccessToken.name
      ::OauthAccessToken.find_by_id(info[:token_id])
    end
  end

  # Sessionless requests are served as the token's user, so a token that only the public
  # access rule admits is denied unless the caller reads what every reader gets.
  def granular_scopes_authorized?(token, permission, subject, allow_public_access: false)
    ::Authz::Tokens::AuthorizeGranularScopesService.new(
      boundaries: ::Authz::Boundary.for(subject),
      permissions: permission,
      token: token,
      allow_public_access: allow_public_access
    ).execute.success?
  end

  # A project boundary also authorizes group- and root-scoped tokens via ancestry.
  def granular_token_boundary
    if respond_to?(:project, true) && project
      project
    elsif respond_to?(:group, true) && group
      group
    else
      ::Authz::GranularScope::Access::USER
    end
  end

  # Overridable for controllers without render_404 (e.g. EventForwardController).
  def deny_granular_token!
    render_404
  end

  def granular_access_token
    token = authentication_result_token
    return unless token.try(:granular?)

    token
  end
  strong_memoize_attr :granular_access_token

  def access_token_authorized?(subject, permission, allow_public_access: false)
    token = authentication_result_token
    return true unless token

    granular_scopes_authorized?(token, permission, subject, allow_public_access: allow_public_access)
  end

  def authentication_result_token
    authentication_result&.access_token
  end
end
