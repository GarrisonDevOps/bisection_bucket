# frozen_string_literal: true

module EE
  module RolesAndPermissions
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    included do
      before_action :ensure_role_exists!, only: [:show, :edit]
    end

    private

    def ensure_role_exists!
      render_404 unless member_role
    end

    def member_role
      id = params.permit(:id)[:id]

      if /\A\d+\z/.match?(id)
        admin_role(id) || ::Members::AllRolesFinder.new(current_user, id: id).execute.first
      else
        access_level = ::Types::MemberAccessLevelEnum.enum[id.downcase]
        name = ::Gitlab::Access.options_with_owner.key(access_level)

        { name: name } if name
      end
    end
    strong_memoize_attr :member_role

    def admin_role(id)
      return unless ::Feature.enabled?(:extract_admin_roles_from_member_roles, :instance)
      return unless can?(current_user, :read_admin_role)

      ::Authz::AdminRole.find_by_id(id)
    end
  end
end
