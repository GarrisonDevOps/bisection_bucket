# frozen_string_literal: true

module EE
  module API
    module Members
      extend ActiveSupport::Concern

      prepended do
        helpers ::GitlabSubscriptions::BilledUsersScanRateLimit

        params do
          requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
        end
        resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Set override flag for a member of a group' do
            detail 'Sets the override flag for a member of a group. By default, the access level of LDAP group ' \
              'members is set to the value specified by LDAP through Group Sync.'
            success ::API::Entities::Member
            tags ['members']
          end
          params do
            requires :user_id, type: Integer, desc: 'ID of the user.'
          end
          route_setting :authorization, permissions: :create_ldap_member_override, boundary_type: :group
          post ":id/members/:user_id/override", feature_category: :user_management do
            group = find_group!(params[:id])
            member = find_member(params)

            result = ::Members::UpdateService
              .new(current_user, { override: true, source: group })
              .execute(member, permission: :override)

            updated_member = result[:members].first

            if result[:status] == :success
              present_members updated_member
            else
              render_validation_error!(updated_member)
            end
          end

          desc 'Remove an LDAP access level override' do
            detail 'Removes an LDAP access level override for a member of a group. Sets the override flag to `false` ' \
              'and allows LDAP Group Sync to reset the access level to the LDAP-prescribed value.'
            success ::API::Entities::Member
            tags ['members']
          end
          params do
            requires :user_id, type: Integer, desc: 'ID of the user.'
          end
          route_setting :authorization, permissions: :delete_ldap_member_override, boundary_type: :group
          delete ":id/members/:user_id/override", feature_category: :user_management do
            group = find_group!(params[:id])
            member = find_member(params)

            result = ::Members::UpdateService
              .new(current_user, { override: false, source: group })
              .execute(member, permission: :override)

            updated_member = result[:members].first

            if result[:status] == :success
              present_members updated_member
            else
              render_validation_error!(updated_member)
            end
          end

          desc 'Approve a group member' do
            detail 'Approves a specified pending user for a top-level group and any subgroups or projects.'
            tags ['members']
          end
          params do
            requires :member_id, type: Integer, desc: 'ID of the member.'
          end
          route_setting :authorization, permissions: :approve_member, boundary_type: :group
          put ':id/members/:member_id/approve', feature_category: :groups_and_projects do
            group = find_group!(params[:id])
            member = ::Member.find_by_id(params[:member_id])

            not_found! unless member
            bad_request! unless group.root?
            bad_request! unless can?(current_user, :activate_group_member, group)

            result =
              if member.invite?
                ::Members::ActivateService.for_invite(group, invite_email: member.invite_email).execute(current_user: current_user)
              else
                ::Members::ActivateService.for_users(group, users: [member.user]).execute(current_user: current_user)
              end

            if result[:status] == :success
              no_content!
            else
              bad_request!(result[:message])
            end
          end

          desc 'Approve all pending group members' do
            detail 'Approves all pending users for a specified top-level group and any subgroups or projects.'
            tags ['members']
          end
          route_setting :authorization, permissions: :approve_member, boundary_type: :group
          post ':id/members/approve_all', feature_category: :groups_and_projects do
            group = find_group!(params[:id])

            bad_request! unless group.root?
            bad_request! unless can?(current_user, :activate_group_member, group)

            result = ::Members::ActivateService.for_group(group).execute(current_user: current_user)

            if result[:status] == :success
              no_content!
            else
              bad_request!(result[:message])
            end
          end

          desc 'List all pending group members' do
            detail 'Lists all members in an `awaiting` state and those who are invited but do not have a GitLab ' \
              'account for a specified group and any subgroups and projects. This operation works on top-level ' \
              'groups only. It does not work on subgroups. You must have permission to administer members of the ' \
              'group. For an invited user who has not signed up for a GitLab account yet, the invited email ' \
              'address is returned.'
            tags ['members']
          end
          params do
            use :pagination
          end
          route_setting :authorization, permissions: :read_pending_member, boundary_type: :group
          get ":id/pending_members", feature_category: :groups_and_projects do
            group = find_group!(params[:id])

            bad_request! unless group.root?
            bad_request! unless can?(current_user, :admin_group_member, group)

            members = ::Member.distinct_awaiting_or_invited_for_group(group)

            present paginate(members), with: ::API::Entities::PendingMember
          end

          desc 'List all billable group members' do
            detail 'Lists all billable members of a specified top-level group. Includes members in any subgroups or ' \
              'projects. You must have the Owner role for the group.'
            success ::API::Entities::Member
            is_array true
            tags ['groups']
          end
          params do
            use :pagination
            optional :search, type: String, desc: 'Query string to search for group members by name, username, or public email.'
            optional :sort, type: String, desc: 'Sort results by the specified field and direction.', values: Helpers::MembersHelpers.member_sort_options
          end
          route_setting :authorization, permissions: :read_billable_member, boundary_type: :group
          get ":id/billable_members", feature_category: :seat_cost_management do
            group = find_group!(params[:id])

            bad_request!(nil) if group.subgroup?
            bad_request!(nil) unless ::Ability.allowed?(current_user, :read_billable_member, group)

            check_billed_users_scan_rate_limit!(group)

            sorting = params[:sort] || 'id_asc'

            result = BilledUsersFinder.new(group, search_term: params[:search], order_by: sorting).execute

            users = result[:users].preload_user_detail
            owners = group.member_owners_excluding_project_bots_and_service_accounts

            present paginate(users),
              with: ::API::Entities::BillableMember,
              current_user: current_user,
              group: group,
              owners: owners,
              group_member_user_ids: result[:group_member_user_ids],
              project_member_user_ids: result[:project_member_user_ids],
              shared_group_user_ids: result[:shared_group_user_ids],
              shared_project_user_ids: result[:shared_project_user_ids]
          end

          desc 'Update group membership state for a user' do
            detail 'Updates the membership state for a specified user in a group. When a user is over the free user ' \
              'limit, changing their membership state to `awaiting` or `active` can allow them to access the group ' \
              'or project. The change is applied to all subgroups and projects.'
            tags %w[members]
          end
          params do
            requires :user_id, type: Integer, desc: 'ID of the user.'
            requires :state, type: String, values: %w[awaiting active], desc: 'New state for the member.'
          end
          route_setting :authorization, permissions: :toggle_state_member, boundary_type: :group
          put ":id/members/:user_id/state", feature_category: :user_management do
            user = find_user(params[:user_id])
            not_found!('User') unless user

            group = find_group(params[:id])
            not_found!('Group') unless group
            bad_request! unless group.root?
            bad_request! unless can?(current_user, :admin_group_member, group)

            result =
              if params[:state] == 'active'
                ::Members::ActivateService.for_users(group, users: [user]).execute(current_user: current_user)
              else
                ::Members::AwaitService.new(group, user: user, current_user: current_user).execute
              end

            if result[:status] == :success
              { success: true }
            else
              unprocessable_entity!(result[:message])
            end
          end

          desc 'List all memberships for a billable group member' do
            detail 'Lists all projects and groups that a specified billable member of a group is a member of. Only ' \
              'projects and groups in the group hierarchy are included. The response represents only direct ' \
              'memberships. Inherited memberships are not included. This operation works on top-level groups only. ' \
              'It does not work on subgroups. You must have permission to administer members of the group.'
            success ::API::Entities::BillableMembership
            is_array true
            tags %w[members]
          end
          params do
            requires :user_id, type: Integer, desc: 'ID of the user.'
            use :pagination
          end
          route_setting :authorization, permissions: :read_billable_member, boundary_type: :group
          get ":id/billable_members/:user_id/memberships", feature_category: :seat_cost_management do
            group = find_group!(params[:id])

            bad_request! unless can?(current_user, :admin_group_member, group)
            bad_request! if group.subgroup?

            user = ::User.find(params[:user_id])

            not_found!('User') unless billable_member?(group, user)

            memberships = user.members.in_hierarchy(group).including_source

            present paginate(memberships), with: ::API::Entities::BillableMembership
          end

          desc 'List all indirect memberships for a billable group member' do
            detail 'Lists all indirect memberships for a billable member of a group. Indirect memberships are the ' \
              'projects and groups that the user is a member of and that were invited to the requested top-level ' \
              'group. This operation works on top-level groups only. It does not work on subgroups. You must have ' \
              'permission to administer members of the group.'
            success ::API::Entities::BillableMembership
            is_array true
            tags %w[members]
          end
          params do
            requires :user_id, type: Integer, desc: 'ID of the user.'
            use :pagination
          end
          route_setting :authorization, permissions: :read_billable_member, boundary_type: :group
          get ":id/billable_members/:user_id/indirect", feature_category: :seat_cost_management do
            group = find_group!(params[:id])

            bad_request! unless can?(current_user, :admin_group_member, group)
            bad_request! if group.subgroup?

            user = ::User.find(params[:user_id])

            not_found!('User') unless billable_member?(group, user)

            exclude_guests = group.exclude_guests?
            invited_group_to_project_memberships = group.billed_invited_group_to_project_members(exclude_guests: exclude_guests).with_user(user.id)
            invited_group_to_group_memberships = group.billed_shared_group_members(exclude_guests: exclude_guests).with_user(user.id)

            invited_memberships = ::GroupMember.from_union([
              invited_group_to_group_memberships,
              invited_group_to_project_memberships
            ])

            present paginate(invited_memberships), with: ::API::Entities::BillableMembership
          end

          desc 'Remove a billable member from a group' do
            detail 'Removes a specified billable member from a group and its subgroups and projects. The user does ' \
              'not need to be a group member to qualify for removal. For example, if the user was added directly to ' \
              'a project in the group, you can still remove them using this operation. Removal is asynchronous and ' \
              'completes in a few minutes.'
            success code: 204, message: 'Resource deleted'
            tags %w[members]
          end
          params do
            requires :user_id, type: Integer, desc: 'ID of the user.'
          end
          route_setting :authorization, permissions: :delete_billable_member, boundary_type: :group
          delete ":id/billable_members/:user_id", feature_category: :seat_cost_management do
            group = find_group!(params[:id])

            check_rate_limit!(:members_delete, scope: { group: group, user: current_user })

            result = ::Members::ScheduleDeletionService.new(group, params[:user_id], current_user).execute

            if result[:status] == :success
              no_content!
            else
              bad_request!(result[:message])
            end
          end
        end
      end
    end
  end
end
