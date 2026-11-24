# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    module SelfManaged
      class AddOnEligibleUsersResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::GitlabSubscriptions::CodeSuggestionsHelper

        type [::Types::GitlabSubscriptions::AddOnUserType.connection_type], null: true

        argument :search,
          type: GraphQL::Types::String,
          required: false,
          description: 'Search the user list.'

        argument :sort,
          type: Types::GitlabSubscriptions::UserSortEnum,
          required: false,
          description: 'Sort the user list.'

        argument :add_on_type,
          type: Types::GitlabSubscriptions::AddOnTypeEnum,
          required: true,
          description: 'Type of add on to filter the eligible users by.'

        argument :add_on_purchase_ids,
          type: [::Types::GlobalIDType[::GitlabSubscriptions::AddOnPurchase]],
          required: true,
          description: 'Global IDs of the add on purchases to find assignments for.',
          prepare: ->(global_ids, _ctx) do
            GitlabSchema.parse_gids(global_ids, expected_type: ::GitlabSubscriptions::AddOnPurchase).map(&:model_id)
          end

        argument :filter_by_assigned_seat,
          type: GraphQL::Types::String,
          required: false,
          description: 'Filter users list by assigned seat.'

        def resolve(add_on_type:, add_on_purchase_ids:, search: nil, sort: nil, filter_by_assigned_seat: nil)
          authorize!

          users = ::GitlabSubscriptions::SelfManaged::AddOnEligibleUsersFinder.new(
            add_on_type: add_on_type,
            add_on_purchase_id: add_on_purchase_ids.first,
            filter_options: {
              search_term: search,
              filter_by_assigned_seat: Gitlab::Utils.to_boolean(filter_by_assigned_seat)
            },
            sort: sort
          ).execute

          offset_pagination(users)
        end

        private

        def authorize!
          return unless gitlab_com_subscription? || !current_user.can_admin_all_resources?

          raise_resource_not_available_error!
        end
      end
    end
  end
end
