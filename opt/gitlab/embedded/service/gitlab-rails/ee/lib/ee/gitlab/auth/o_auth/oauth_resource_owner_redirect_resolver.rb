# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module OAuth
        module OauthResourceOwnerRedirectResolver
          include ::Gitlab::Routing
          extend ::Gitlab::Utils::Override

          override :resolve_redirect_url
          def resolve_redirect_url
            root_namespace_id = request.query_parameters['root_namespace_id']
            return super if root_namespace_id.blank?

            group = ::Group.find_by_id(root_namespace_id)
            return super unless group

            sso_url = build_sso_redirect_url(group)

            return super if sso_url.blank?

            session[:user_sso_return_to] = request.fullpath
            sso_url
          end

          private

          def build_sso_redirect_url(group)
            return unless group.enforced_sso?

            redirector = ::RoutableActions::SsoEnforcementRedirect.new(group, group.full_path)
            redirector.sso_redirect_url
          end
        end
      end
    end
  end
end
