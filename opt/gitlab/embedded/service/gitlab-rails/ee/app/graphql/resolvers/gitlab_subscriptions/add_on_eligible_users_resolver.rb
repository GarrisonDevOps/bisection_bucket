# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    class AddOnEligibleUsersResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ::GitlabSubscriptions::CodeSuggestionsHelper

      argument :sort,
        type: Types::GitlabSubscriptions::UserSortEnum,
        required: false,
        description: 'Sort the user list.'

      argument :search,
        type: GraphQL::Types::String,
        required: false,
        description: 'Search the user list.'

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

      type ::Types::GitlabSubscriptions::AddOnUserType.connection_type,
        null: true

      alias_method :namespace, :object

      def resolve(add_on_type:, add_on_purchase_ids:, search: nil, sort: nil, filter_by_assigned_seat: nil)
        authorize!(namespace)

        add_on_purchase_id = add_on_purchase_ids.first
        return unless purchase_belongs_to_namespace?(add_on_purchase_id)

        users = ::GitlabSubscriptions::AddOnEligibleUsersFinder.new(
          namespace,
          add_on_type: add_on_type,
          filter_options: {
            search_term: search,
            filter_by_assigned_seat: Gitlab::Utils.to_boolean(filter_by_assigned_seat)
          },
          sort: sort,
          add_on_purchase_id: add_on_purchase_id
        ).execute

        offset_pagination(users)
      end

      private

      def authorize!(namespace)
        raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_add_on_purchase, namespace)

        return if namespace.root?

        raise_resource_not_available_error!("Add on eligible users can only be queried on a root namespace")
      end

      def purchase_belongs_to_namespace?(add_on_purchase_id)
        return true if add_on_purchase_id.blank?

        ::GitlabSubscriptions::AddOnPurchase.by_namespace(namespace).id_in(add_on_purchase_id).exists?
      end
    end
  end
end
