# frozen_string_literal: true

module EE
  module API
    module Helpers
      module MembersHelpers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class << self
          def member_sort_options
            %w[
              access_level_asc access_level_desc last_joined name_asc name_desc oldest_joined oldest_sign_in
              recent_sign_in last_activity_on_asc last_activity_on_desc
            ]
          end
        end

        prepended do
          params :optional_filter_params_ee do
            optional :with_saml_identity, type: Grape::API::Boolean, desc: 'If `true`, returns only members with a ' \
                                                                       'linked SAML identity.'
          end

          params :optional_state_filter_ee do
            optional :state, type: String, desc: 'Filter results by member state. Premium and Ultimate ' \
                                             'only.', values: %w[awaiting active]
          end

          params :optional_put_params_ee do
            optional :member_role_id, type: Integer, desc: 'ID of a custom member role to assign to the member. ' \
                                                       'Set to `null` to remove all custom roles. Ultimate only.'
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :member_access_levels
          def member_access_levels
            super + [::Gitlab::Access::MINIMAL_ACCESS]
          end
        end

        # rubocop: disable CodeReuse/ActiveRecord
        override :retrieve_members
        def retrieve_members(source, params:, deep: false)
          members = super
          members = members.includes(user: [:user_highest_role, :user_detail])

          if can_view_group_identity?(source)
            members = members.includes(user: :group_saml_identities)
            if params[:with_saml_identity] && source.saml_provider
              members = members.with_saml_identity(source.saml_provider)
            end
          end

          members = members.where.not(user_id: params[:skip_users]) if params[:skip_users].present?
          members = members.with_state(params[:state]) if params[:state].present?

          members
        end

        override :source_members
        def source_members(source)
          return super if source.is_a?(Project)
          return super unless source.minimal_access_role_allowed?

          source.all_group_members
        end
        # rubocop: enable CodeReuse/ActiveRecord

        def can_view_group_identity?(members_source)
          can?(current_user, :read_group_saml_identity, members_source)
        end

        def find_member(params)
          source = find_source(:group, params.delete(:id))
          authorize! :override_group_member, source

          source.members.by_user_id(params[:user_id]).first
        end

        def billable_member?(group, user)
          billed_users_finder = BilledUsersFinder.new(group)
          users = billed_users_finder.execute[:users]

          users.include?(user)
        end

        override :present_put_membership_response
        def present_put_membership_response(result)
          if result[:status] != :error && result[:members_queued_for_approval].present?
            member = result[:members_queued_for_approval].first

            return accepted!({
              member.user.username => _("Request queued for administrator approval.")
            })
          end

          super
        end

        private

        override :present_add_single_member_response
        def present_add_single_member_response(result, _member)
          return accepted!(result[:queued_users]) if result[:status] != :error && result[:queued_users].present?

          super
        end
      end
    end
  end
end
