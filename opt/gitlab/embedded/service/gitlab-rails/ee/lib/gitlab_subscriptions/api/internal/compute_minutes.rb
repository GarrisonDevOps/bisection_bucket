# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class ComputeMinutes < ::API::Base
        feature_category :consumables_cost_management
        urgency :low

        CI_MINUTES_TAGS = %w[ci_minutes].freeze

        namespace :internal do
          namespace :gitlab_subscriptions do
            resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
              desc 'Create a compute minutes purchase record for the namespace' do
                detail 'Creates an additional pack'
                success Entities::Internal::Ci::Minutes::AdditionalPack
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
                is_array true
                tags CI_MINUTES_TAGS
              end
              params do
                requires :id, type: String, desc: 'The ID of a namespace'
                requires :packs, type: Array, desc: 'An array of additional purchased minutes packs' do
                  requires :number_of_minutes, type: Integer, desc: 'Number of additional minutes purchased'
                  requires :expires_at, type: Date, desc: 'The expiry date for the purchase'
                  requires :purchase_xid, type: String, desc: 'Purchase ID for the additional minutes'
                end
              end
              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              post ':id/minutes' do
                namespace = find_namespace(params[:id])
                not_found!('Namespace') unless namespace

                result = ::Ci::Minutes::AdditionalPacks::CreateService.new(namespace, params[:packs]).execute

                if result[:status] == :success
                  present result[:additional_packs], with: Entities::Internal::Ci::Minutes::AdditionalPack
                else
                  bad_request!(result[:message])
                end
              end

              desc 'Transfer purchased compute minutes packs to another namespace' do
                detail 'Moves additional packs from one namespace to another'
                success code: 202
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
                tags CI_MINUTES_TAGS
              end
              params do
                requires :id, type: String, desc: 'The ID of the namespace to transfer from'
                requires :target_id, type: String, desc: 'The ID of the namespace for the packs to transfer to'
              end
              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              patch ':id/minutes/move/:target_id' do
                namespace = find_namespace(params[:id])
                target_namespace = find_namespace(params[:target_id])

                not_found!('Namespace') unless namespace
                not_found!('Target namespace') unless target_namespace

                result = ::Ci::Minutes::AdditionalPacks::ChangeNamespaceService.new(namespace, target_namespace).execute

                if result[:status] == :success
                  accepted!
                else
                  bad_request!(result[:message])
                end
              end
            end
          end
        end
      end
    end
  end
end
