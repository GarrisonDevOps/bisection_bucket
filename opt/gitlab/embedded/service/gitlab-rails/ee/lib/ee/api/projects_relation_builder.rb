# frozen_string_literal: true

module EE
  module API
    module ProjectsRelationBuilder
      extend ::Gitlab::Utils::Override

      override :preload_member_roles
      def preload_member_roles(projects_relation, user)
        ::Preloaders::UserMemberRolesInProjectsPreloader.new(
          projects: projects_relation,
          user: user
        ).execute
      end

      override :preload_groups
      def preload_groups(projects_relation)
        groups = super

        ::Gitlab::GroupPlansPreloader.new.preload(groups) # rubocop:disable CodeReuse/ActiveRecord -- not an ActiveRecord method
      end
    end
  end
end
