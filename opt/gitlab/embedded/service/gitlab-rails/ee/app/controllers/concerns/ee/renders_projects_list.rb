# frozen_string_literal: true

module EE
  module RendersProjectsList
    extend ::Gitlab::Utils::Override

    override :preload_member_roles
    def preload_member_roles(projects)
      ::Authz::Project.new(current_user, scope: projects).permitted
    end
  end
end
