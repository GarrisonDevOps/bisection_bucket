# frozen_string_literal: true

module EE
  module Projects
    module TargetProjects
      extend ActiveSupport::Concern

      private

      def get_target_projects
        return super unless params[:action] == "target_projects_json"

        filter_out_saml_groups(super)
      end

      def filter_out_saml_groups(projects)
        groups = target_groups(projects)
        return projects unless groups.any?

        filter_groups = saml_groups(groups, current_user)
        return projects unless filter_groups.any?

        projects.not_in_groups(filter_groups)
      end

      def saml_groups(groups, current_user)
        @saml_groups ||= ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted_groups(groups,
          user: current_user)
      end

      def target_groups(projects)
        @target_groups ||= projects.filter_map(&:group)
      end
    end
  end
end
