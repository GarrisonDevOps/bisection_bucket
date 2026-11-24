# frozen_string_literal: true

module EE
  module Projects
    module ProjectMembersController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      MEMBER_PER_PAGE_LIMIT = 50

      override :index
      def index
        super

        return if request.format.json?

        @pending_promotion_members_count = pending_promotion_members_count
      end

      private

      prepended do
        before_action :disable_query_limiting, only: [:index]

        before_action do
          push_frontend_feature_flag(:show_overage_on_role_promotion)
        end
      end

      def disable_query_limiting
        ::Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/work_items/591741', new_threshold: 110)
      end

      override :invited_members
      def invited_members
        super.or(members.awaiting.with_invited_user_state)
      end

      override :non_invited_members
      def non_invited_members
        super.non_awaiting
      end

      def pending_promotion_members_count
        return unless can?(current_user, :admin_project_member, project)

        ::GitlabSubscriptions::MemberManagement::MemberApprovalFinder
          .new(current_user: current_user, source: project)
          .execute
          .count
      end
    end
  end
end
