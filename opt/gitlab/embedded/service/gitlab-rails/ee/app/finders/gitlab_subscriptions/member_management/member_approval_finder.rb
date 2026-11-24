# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MemberApprovalFinder
      include GitlabSubscriptions::MemberManagement::PromotionManagementUtils

      attr_reader :params

      def initialize(current_user:, source:, params: {})
        @current_user = current_user
        @params = params
        validate_and_set_source(source)
      end

      def execute
        model = ::GitlabSubscriptions::MemberManagement::MemberApproval
        return model.none unless member_promotion_management_enabled?
        return model.none unless allowed_to_query_member_approvals?

        model.pending_member_approvals(@member_namespace_id)
      end

      private

      attr_reader :current_user, :source, :member_namespace_id, :type

      def validate_and_set_source(source)
        case source
        when ::Group
          @member_namespace_id = source.id
          @type = :group
        when ::Project
          @member_namespace_id = source.project_namespace.id
          @type = :project
        else
          raise ArgumentError, 'Invalid source. Source should be either Group or Project.'
        end
        @source = source
      end

      def allowed_to_query_member_approvals?
        ability = case type
                  when :group
                    :admin_group_member
                  when :project
                    :admin_project_member
                  end

        Ability.allowed?(current_user, ability, source)
      end
    end
  end
end
