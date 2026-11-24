# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module UserAddOnAssignments
      class Remove < BaseMutation
        graphql_name 'UserAddOnAssignmentRemove'
        include ::GitlabSubscriptions::CodeSuggestionsHelper

        argument :add_on_purchase_id, ::Types::GlobalIDType[::GitlabSubscriptions::AddOnPurchase],
          required: true, description: 'Global ID of AddOnPurchase assignment belongs to.'

        argument :user_id, ::Types::GlobalIDType[::User],
          required: true, description: 'Global ID of user whose assignment will be removed.'

        field :add_on_purchase, ::Types::GitlabSubscriptions::AddOnPurchaseType,
          null: true,
          description: 'AddOnPurchase state after mutation.'
        field :user, ::Types::GitlabSubscriptions::AddOnUserType,
          null: true,
          description: 'User that the add-on was removed from.'

        authorize :delete_add_on_assignment

        authorize_granular_token permissions: :delete_add_on_assignment,
          boundaries: [
            { boundary_argument: :add_on_purchase_id, boundary: :namespace, boundary_type: :group },
            { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
          ]

        def resolve(**)
          assignment = add_on_purchase.assigned_users.by_user(user_to_be_removed).first

          return unless assignment

          assignment.destroy!

          Rails.cache.delete(::Ai::UserAuthorizer.duo_pro_cache_key_formatted(user_to_be_removed.id))

          log_event

          {
            add_on_purchase: add_on_purchase,
            user: user_to_be_removed,
            errors: []
          }
        end

        def ready?(add_on_purchase_id:, user_id:)
          @add_on_purchase = authorized_find!(id: add_on_purchase_id)
          @user_to_be_removed = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(user_id))

          raise_resource_not_available_error! unless add_on_purchase&.active? && user_to_be_removed

          super
        end

        private

        attr_reader :add_on_purchase, :user_to_be_removed

        def log_event
          Gitlab::AppLogger.info(
            message: 'User AddOn assignment removed',
            username: user_to_be_removed.username.to_s,
            add_on: add_on_purchase.add_on.name,
            namespace: add_on_purchase.namespace&.path
          )
        end
      end
    end
  end
end
