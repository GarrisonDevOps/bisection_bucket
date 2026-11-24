# frozen_string_literal: true

module API
  module Ci
    class Minutes < ::API::Base
      feature_category :subscription_management
      urgency :low

      CI_MINUTES_TAGS = %w[ci_minutes].freeze
      resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        desc 'Create a compute minutes purchase record for the namespace' do
          detail 'Deprecated in GitLab 17.7'
          success ::API::Entities::Ci::Minutes::AdditionalPack
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Not found' }
          ]
          is_array true
          tags CI_MINUTES_TAGS
          deprecated true
        end
        params do
          requires :id, type: String, desc: 'ID of the namespace.'
          requires :packs, type: Array, desc: 'Array of additional purchased minute packs.' do
            requires :number_of_minutes, type: Integer, desc: 'Number of additional minutes purchased.'
            requires :expires_at, type: Date, desc: 'Date when the purchase expires.'
            requires :purchase_xid, type: String, desc: 'Purchase ID for the additional minutes.'
          end
        end
        route_setting :authorization,
          permissions: :create_ci_minute,
          boundaries: [{ boundary_type: :group }, { boundary_type: :user }],
          assignable_when: [:admin]
        post ':id/minutes' do
          namespace = find_namespace(params[:id])
          not_found!('Namespace') unless namespace

          result = ::Ci::Minutes::AdditionalPacks::CreateService.new(namespace, params[:packs]).execute

          if result[:status] == :success
            present result[:additional_packs], with: ::API::Entities::Ci::Minutes::AdditionalPack
          else
            bad_request!(result[:message])
          end
        end

        desc 'Transfer purchased compute minutes packs to another namespace' do
          detail 'Deprecated in GitLab 17.7'
          success code: 202
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Not found' }
          ]
          tags CI_MINUTES_TAGS
          deprecated true
        end
        params do
          requires :id, type: String, desc: 'ID of the namespace to transfer from.'
          requires :target_id, type: String, desc: 'ID of the namespace for the packs to transfer to.'
        end
        route_setting :authorization,
          permissions: :transfer_ci_minute,
          boundaries: [{ boundary_type: :group }, { boundary_type: :user }],
          assignable_when: [:admin]
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
