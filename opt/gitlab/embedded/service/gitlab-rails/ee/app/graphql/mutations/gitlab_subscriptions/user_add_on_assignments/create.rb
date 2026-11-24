# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module UserAddOnAssignments
      class Create < BaseMutation
        graphql_name 'UserAddOnAssignmentCreate'
        include ::GitlabSubscriptions::CodeSuggestionsHelper

        argument :add_on_purchase_id, ::Types::GlobalIDType[::GitlabSubscriptions::AddOnPurchase],
          required: true, description: 'Global ID of AddOnPurchase to be assigned to.'

        argument :user_id, ::Types::GlobalIDType[::User],
          required: true, description: 'Global ID of user to be assigned.'

        field :add_on_purchase, ::Types::GitlabSubscriptions::AddOnPurchaseType,
          null: true,
          description: 'AddOnPurchase state after mutation.'

        field :user, ::Types::GitlabSubscriptions::AddOnUserType,
          null: true,
          description: 'User who the add-on purchase was assigned to.'

        authorize :create_add_on_assignment

        authorize_granular_token permissions: :create_add_on_assignment,
          boundaries: [
            { boundary_argument: :add_on_purchase_id, boundary: :namespace, boundary_type: :group },
            { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
          ]

        def resolve(**)
          create_service = create_user_add_on_service.execute

          if create_service.success?
            {
              add_on_purchase: add_on_purchase,
              user: user_to_be_assigned,
              errors: create_service.errors
            }
          else
            { errors: create_service.errors }
          end
        end

        def ready?(add_on_purchase_id:, user_id:)
          @add_on_purchase = authorized_find!(id: add_on_purchase_id)
          @user_to_be_assigned = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(user_id))

          raise_resource_not_available_error! unless add_on_purchase&.active? && user_to_be_assigned

          super
        end

        private

        attr_reader :add_on_purchase, :user_to_be_assigned

        def create_user_add_on_service
          service_class = if gitlab_com_subscription?
                            ::GitlabSubscriptions::UserAddOnAssignments::Saas::CreateService
                          else
                            ::GitlabSubscriptions::UserAddOnAssignments::SelfManaged::CreateService
                          end

          service_class.new(add_on_purchase: add_on_purchase, user: user_to_be_assigned)
        end
      end
    end
  end
end
