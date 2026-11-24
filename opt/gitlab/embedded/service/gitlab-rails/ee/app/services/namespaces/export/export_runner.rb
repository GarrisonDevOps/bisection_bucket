# frozen_string_literal: true

module Namespaces
  module Export
    class ExportRunner
      attr_reader :group, :current_user

      def initialize(group, current_user)
        @group = group
        @current_user = current_user
      end

      def execute
        authorize_can_export!

        ::Members::Groups::ExportDetailedMembershipsWorker.perform_async(group.id, current_user.id)

        ServiceResponse.success
      end

      private

      def authorize_can_export!
        return if Ability.allowed?(current_user, :export_group_memberships, group)

        raise Gitlab::Access::AccessDeniedError, 'User unauthorized to export group members.'
      end
    end
  end
end
