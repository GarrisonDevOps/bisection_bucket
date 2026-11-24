# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class Namespaces
        class Provision < ::API::Base
          feature_category :plan_provisioning
          urgency :low

          namespace :internal do
            namespace :gitlab_subscriptions do
              resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
                before do
                  @namespace = find_namespace(params[:id])

                  not_found!('Namespace') unless @namespace
                  bad_request!('Must be root namespace') unless @namespace.root?
                end

                helpers do
                  params :base_product do
                    optional :plan_code, type: String, desc: 'The plan code for subscription'
                    optional :start_date, type: Date, desc: 'Start date of subscription'
                    optional :end_date, type: Date, desc: 'End date of subscription'
                    optional :seats, type: Integer, desc: 'Number of seats'
                    optional :max_seats_used, type: Integer, desc: 'Max seats used'
                    optional :trial, type: Boolean, desc: 'Whether subscription is a trial'
                    optional :trial_starts_on, type: Date, desc: 'Trial start date'
                    optional :trial_ends_on, type: Date, desc: 'Trial end date'
                    optional :auto_renew, type: Boolean, desc: 'Whether subscription auto renews'
                    optional :contract_overages_allowed, type: Boolean, desc: 'Whether contract overages are allowed'
                  end

                  params :compute_minutes do
                    optional :shared_runners_minutes_limit, type: Integer, desc: 'Base minutes included in plan'
                    optional :extra_shared_runners_minutes_limit, type: Integer, desc: 'Additional purchased minutes'
                  end

                  params :storage do
                    optional :additional_purchased_storage_size, type: Integer, desc: 'Additional storage size'
                    optional :additional_purchased_storage_ends_on, type: Date, desc: 'Additional storage end date'
                  end
                end

                desc 'Provision a namespace' do
                  detail 'Complete provisioning of a namespace with base product, add-on purchases,' \
                    'compute minutes, and storage'
                  success Entities::Internal::ProvisionResult
                  failure [
                    { code: 400, message: 'Bad Request' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 404, message: 'Not Found' },
                    { code: 422, message: 'Unprocessable Entity' }
                  ]
                end
                params do
                  requires :provision, type: Hash, desc: 'Provisioning data' do
                    optional :base_product, type: Hash, desc: 'Base product subscription details' do
                      use :base_product
                    end
                    optional :compute_minutes, type: Hash, desc: 'Compute minutes details' do
                      use :compute_minutes
                    end
                    optional :storage, type: Hash, desc: 'Storage details' do
                      use :storage
                    end
                    optional :add_on_purchases, type: Hash,
                      desc: 'Add-on purchases indexed by add-on name. Each add-on accepts: ' \
                        'started_on (Date, required), expires_on (Date, required), ' \
                        'quantity (Integer, non-negative), purchase_xid (String), trial (Boolean), ' \
                        'new_subscription (Boolean)'
                  end
                end

                route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
                post ':id/provision' do
                  result = ::GitlabSubscriptions::Provision::SyncNamespaceService.new(
                    namespace: @namespace,
                    params: declared_params(include_missing: false)[:provision]
                  ).execute
                  status result.success? ? :ok : :unprocessable_entity
                  present result, with: Entities::Internal::ProvisionResult
                end
              end
            end
          end
        end
      end
    end
  end
end
