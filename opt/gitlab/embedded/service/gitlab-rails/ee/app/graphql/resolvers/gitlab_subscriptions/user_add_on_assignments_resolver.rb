# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    class UserAddOnAssignmentsResolver < BaseResolver
      include LooksAhead
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ::GitlabSubscriptions::CodeSuggestionsHelper

      argument :add_on_purchase_ids,
        type: [::Types::GlobalIDType[::GitlabSubscriptions::AddOnPurchase]],
        required: true,
        description: 'Global IDs of the add on purchases to find assignments for.',
        prepare: ->(global_ids, _ctx) do
          GitlabSchema.parse_gids(global_ids, expected_type: ::GitlabSubscriptions::AddOnPurchase).map(&:model_id)
        end

      type ::Types::GitlabSubscriptions::UserAddOnAssignmentType.connection_type, null: true

      alias_method :user, :object

      def resolve_with_lookahead(**args)
        BatchLoader::GraphQL.for(user.id).batch do |user_ids, loader|
          query = ::GitlabSubscriptions::UserAddOnAssignment
                    .for_user_ids(user_ids)
                    .for_active_add_on_purchase_ids(args[:add_on_purchase_ids])

          query = query.with_namespaces if gitlab_com_subscription?

          user_assignments = apply_lookahead(query)

          if gitlab_com_subscription?
            namespaces_for_auth = user_assignments.map { |assignment| assignment.add_on_purchase.namespace }
            Preloaders::GroupPolicyPreloader.new(namespaces_for_auth, current_user).execute
          end

          grouped_assignments = user_assignments.group_by(&:user_id)

          user_ids.each { |user_id| loader.call(user_id, grouped_assignments.fetch(user_id, [])) }
        end
      end

      private

      def preloads
        {
          add_on_purchase: [add_on_purchase: [{ namespace: :saml_provider }]],
          [:add_on_purchase, :assigned_quantity] =>
           [{ add_on_purchase: [:assigned_users, { namespace: :saml_provider }] }]
        }
      end
    end
  end
end
