# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module UserAddOnAssignments
      class BulkRemove < BaseMutation
        graphql_name 'UserAddOnAssignmentBulkRemove'
        MAX_USER_UNASSIGNMENT_LIMIT = 100
        MAX_USER_UNASSIGNMENT_ERROR = "The number of users to be unassigned in a single API call " \
                                      "should be less than #{MAX_USER_UNASSIGNMENT_LIMIT}."
                                      .freeze
        include ::GitlabSubscriptions::CodeSuggestionsHelper

        argument :add_on_purchase_id, ::Types::GlobalIDType[::GitlabSubscriptions::AddOnPurchase],
          required: true, description: 'Global ID of AddOnPurchase to be unassigned from.'

        argument :user_ids,
          type: [::Types::GlobalIDType[::User]],
          required: true,
          description: 'Global IDs of user to be unassigned.',
          prepare: ->(global_ids, _ctx) { global_ids&.filter_map { |gid| gid.model_id.to_i } }

        field :add_on_purchase, ::Types::GitlabSubscriptions::AddOnPurchaseType,
          null: true,
          description: 'AddOnPurchase state after mutation.'

        field :users,
          type: ::Types::GitlabSubscriptions::AddOnUserType.connection_type,
          null: true,
          description: 'Users who was unassigned from the add-on purchase.'

        authorize :delete_add_on_assignment

        authorize_granular_token permissions: :delete_add_on_assignment,
          boundaries: [
            { boundary_argument: :add_on_purchase_id, boundary: :namespace, boundary_type: :group },
            { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
          ]

        def resolve(**args)
          result = ::GitlabSubscriptions::Duo::BulkUnassignService.new(
            add_on_purchase: add_on_purchase,
            user_ids: args[:user_ids]
          ).execute

          if result.success?
            {
              add_on_purchase: add_on_purchase,
              users: result[:users],
              errors: []
            }
          else
            { errors: result.errors }
          end
        end

        def ready?(add_on_purchase_id:, user_ids:)
          @add_on_purchase = authorized_find!(id: add_on_purchase_id)

          if user_ids.size > MAX_USER_UNASSIGNMENT_LIMIT
            raise Gitlab::Graphql::Errors::ArgumentError, MAX_USER_UNASSIGNMENT_ERROR
          end

          raise_resource_not_available_error! unless add_on_purchase&.active? && user_ids.any?

          super
        end

        private

        attr_reader :add_on_purchase
      end
    end
  end
end
