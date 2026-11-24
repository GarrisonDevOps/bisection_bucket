# frozen_string_literal: true

module EE
  module Resolvers
    module ProjectsResolver
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        argument :include_hidden, GraphQL::Types::Boolean,
          required: false,
          description: 'Include hidden projects.'

        argument :duo_licensed_feature, ::Types::Ai::DuoLicensedFeatureEnum,
          required: false,
          experiment: { milestone: '18.11' },
          description: "Include only projects eligible for the specified GitLab Duo licensed feature. " \
            "Results are automatically filtered to projects where the user has the Maintainer or Owner role."

        before_connection_authorization do |projects, current_user|
          ::Preloaders::UserMaxAccessLevelInProjectsPreloader.new(projects, current_user).execute
          ::Preloaders::UserMemberRolesInProjectsPreloader.new(projects: projects, user: current_user).execute
        end
      end

      private

      override :finder_params
      def finder_params(args)
        super(args)
          .merge(
            args.slice(
              :include_hidden,
              :duo_licensed_feature
            )
          )
          .merge(filter_expired_saml_session_projects: true)
      end
    end
  end
end
