# frozen_string_literal: true

module EE
  module Resolvers
    module UserStarredProjectsResolver # rubocop:disable Gitlab/BoundedContexts -- needs same bounded context as CE version
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        before_connection_authorization do |projects, current_user|
          ::Preloaders::UserMaxAccessLevelInProjectsPreloader.new(projects, current_user).execute
          ::Preloaders::UserMemberRolesInProjectsPreloader.new(projects: projects, user: current_user).execute
        end
      end

      private

      override :finder_params
      def finder_params(args)
        super.merge(filter_expired_saml_session_projects: true)
      end
    end
  end
end
