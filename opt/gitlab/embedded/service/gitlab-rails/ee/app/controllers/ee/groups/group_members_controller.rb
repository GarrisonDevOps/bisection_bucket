# frozen_string_literal: true

module EE
  module Groups
    module GroupMembersController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      MEMBER_PER_PAGE_LIMIT = 50

      class_methods do
        extend ::Gitlab::Utils::Override

        override :admin_not_required_endpoints
        def admin_not_required_endpoints
          super.concat(%i[update override export_csv ban unban])
        end
      end

      prepended do
        # This before_action needs to be redefined so we can use the new values
        # from `admin_not_required_endpoints`.
        before_action :authorize_admin_group_member!, except: admin_not_required_endpoints
        before_action :authorize_ban_group_member!, only: [:ban]
        before_action :authorize_unban_group_member!, only: [:unban]
        before_action :authorize_update_group_member!, only: [:update, :override]

        before_action do
          push_frontend_feature_flag(:show_overage_on_role_promotion)
          push_licensed_feature(:unique_project_download_limit, @group)
        end
      end

      override :index
      def index
        super

        @banned = presented_banned_members
        @memberships_with_custom_role = present_group_members(group_memberships_with_custom_role)
        @pending_promotion_members_count = pending_promotion_members_count
      end

      def override
        member = membershipable_members.find(id_param)

        result = ::Members::UpdateService.new(current_user, override_params).execute(member, permission: :override)

        respond_to do |format|
          format.js do
            if result[:status] == :success
              head :ok
            else
              render json: result[:message], status: :unprocessable_entity
            end
          end
        end
      end

      def export_csv
        return render_404 unless Ability.allowed?(current_user, :export_group_memberships, group)

        ::Groups::ExportMembershipsWorker.perform_async(group.id, current_user.id)

        redirect_to group_group_members_path(group), notice: _('CSV is being generated and will be emailed to you upon completion.')
      end

      def ban
        member = members.find(id_param)

        result = ::Users::Abuse::NamespaceBans::CreateService.new(current_user: current_user, user: member.user, namespace: group).execute

        if result.success?
          redirect_to group_group_members_path, notice: _("User was successfully banned.")
        else
          redirect_to group_group_members_path, alert: result.message
        end
      end

      def unban
        member = banned_members.find(id_param)
        ban = member.user.namespace_ban_for(group)

        result = ::Users::Abuse::NamespaceBans::DestroyService.new(ban, current_user).execute

        redirect_url = group_group_members_path(tab: 'banned')

        if result.success?
          redirect_to redirect_url, notice: _("User was successfully unbanned.")
        else
          redirect_to redirect_url, alert: result.message
        end
      end

      protected

      override :invited_members
      def invited_members
        super.or(members.awaiting.with_invited_user_state)
      end

      override :search_invited_members
      def search_invited_members(invited_members, query)
        enterprise_group = enterprise_group_with_readable_emails
        return super unless enterprise_group

        invited_members.search_by_invite_email_or_user(query, enterprise_group: enterprise_group)
      end

      # Matches what the members table shows: enterprise users' emails are only visible
      # to users who can read them in the top-level group.
      def enterprise_group_with_readable_emails
        root_group = group.root_ancestor
        return unless root_group.domain_verification_available?
        return unless can?(current_user, :read_email_enterprise_user, root_group)

        root_group
      end

      override :non_invited_members
      def non_invited_members
        members = super.non_awaiting

        if group.unique_project_download_limit_enabled?
          members.where.not(id: banned_members) # rubocop: disable CodeReuse/ActiveRecord
        else
          members
        end
      end

      def presented_banned_members
        return unless group.unique_project_download_limit_enabled?

        present_members(banned_members(params: filter_params))
      end

      def group_memberships_with_custom_role
        @memberships_with_custom_role ||=
          ::GroupMembersFinder
            .new(group, current_user, params: filter_params.merge({ non_invite: true, with_custom_role: true }))
            .execute(include_relations: requested_relations)
      end

      def authorize_update_group_member!
        unless can?(current_user, :admin_group_member, group) || can?(current_user, :override_group_member, group)
          render_403
        end
      end

      def authorize_ban_group_member!
        render_403 unless can?(current_user, :ban_group_member, group)
      end

      def authorize_unban_group_member!
        render_403 unless can?(current_user, :unban_group_member, group)
      end

      def override_params
        params.require(:group_member).permit(:override).merge({ source: source })
      end

      override :membershipable_members
      def membershipable_members
        return super unless group.licensed_feature_available?(:minimal_access_role)

        group.all_group_members
      end

      override :filter_params
      def filter_params
        super.merge(params.permit(:enterprise))
      end

      private

      def id_param
        params.permit(:id)[:id]
      end

      def banned_members(params: {})
        # User bans are enforced at the top-level group. Here, we return all
        # members of the group hierarchy that are banned from the top-level
        # group
        @banned_members ||= ::GroupMembersFinder
          .new(group, current_user, params: params)
          .execute(include_relations: %i[direct descendants])
          .banned_from(group)
      end

      def pending_promotion_members_count
        return unless can?(current_user, :admin_group_member, group)

        ::GitlabSubscriptions::MemberManagement::MemberApprovalFinder
          .new(current_user: current_user, source: group)
          .execute
          .count
      end
    end
  end
end
