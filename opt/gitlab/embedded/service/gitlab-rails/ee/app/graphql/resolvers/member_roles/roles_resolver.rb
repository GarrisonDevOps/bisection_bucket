# frozen_string_literal: true

module Resolvers
  module MemberRoles
    class RolesResolver < BaseResolver
      include LooksAhead

      type Types::MemberRoles::MemberRoleType, null: true

      argument :assignable, GraphQL::Types::Boolean,
        required: false,
        description: 'Filter for member roles the current user can assign.'

      argument :id, ::Types::GlobalIDType[::MemberRole],
        required: false,
        description: 'Global ID of the member role to look up.',
        prepare: ->(global_id, _ctx) { global_id.model_id }

      argument :ids, [::Types::GlobalIDType[::MemberRole]],
        required: false,
        description: 'Global IDs of the member role to look up.',
        prepare: ->(global_ids, _ctx) { global_ids.filter_map(&:model_id) }

      argument :order_by, ::Types::MemberRoles::OrderByEnum,
        required: false,
        description: 'Ordering column. Default is NAME.'

      argument :sort, ::Types::SortDirectionEnum,
        required: false,
        description: 'Ordering column. Default is ASC.'

      def resolve_with_lookahead(id: nil, ids: [], order_by: nil, sort: nil, assignable: nil)
        ids.unshift(id) if id.present?

        params = {}
        params = { parent: object } if object
        params[:id] = ids if ids.present?
        params[:order_by] = order_by.presence || :name
        params[:sort] = sort.present? ? sort.to_sym : :asc
        params[:assignable] = assignable

        member_roles = roles_finder.new(current_user, params).execute
        member_roles = apply_selected_field_scopes(member_roles)

        offset_pagination(member_roles)
      end

      private

      def apply_selected_field_scopes(member_roles)
        member_roles = member_roles.with_members_count if selects_field?(:members_count)
        member_roles = member_roles.with_users_count if selects_field?(:users_count)

        member_roles
      end

      def roles_finder
        ::MemberRoles::RolesFinder
      end

      def selected_fields
        node_selection.selections.map(&:name)
      end

      def selects_field?(name)
        lookahead.selects?(name) || selected_fields.include?(name)
      end
    end
  end
end
