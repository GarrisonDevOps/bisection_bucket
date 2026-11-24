# frozen_string_literal: true

module EE
  # ContributedProjectsFinder
  #
  # Extends ContributedProjectsFinder
  #
  # Added arguments:
  #   params:
  #     filter_expired_saml_session_projects: boolean
  module ContributedProjectsFinder # rubocop:disable Gitlab/BoundedContexts -- needs same bounded context as CE version
    include Gitlab::Auth::Saml::SsoSessionFilterable
    extend ::Gitlab::Utils::Override

    private

    override :filter_projects
    def filter_projects(collection)
      filter_by_saml_sso_session(super, :filter_expired_saml_session_projects)
    end
  end
end
