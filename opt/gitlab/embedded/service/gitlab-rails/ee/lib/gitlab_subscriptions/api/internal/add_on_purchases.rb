# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class AddOnPurchases < ::API::Base
        feature_category :"add-on_provisioning"
        urgency :low

        namespace :internal do
          namespace :gitlab_subscriptions do
            resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
              before do
                @namespace = find_namespace(params[:id])
                not_found!('Namespace') unless @namespace

                @add_on = find_subscription_add_on!(params[:add_on_name]) if params[:add_on_name]
              end

              desc 'Create or update multiple add-on purchases for the namespace' do
                detail 'Create or update multiple subscription add-on records for the given namespace'
                success Entities::Internal::GitlabSubscriptions::AddOnPurchase
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
              end

              helpers do
                params :add_on do
                  requires :started_on, type: Date, desc: 'The date when purchase takes effect'
                  requires :expires_on, type: Date, desc: 'The date when purchase expires on'
                  optional :quantity, type: Integer, values: 0.., desc: 'The quantity of the purchase'
                  optional :purchase_xid, type: String,
                    desc: 'The purchase identifier  (example: the subscription name)'
                  optional :trial, type: Boolean, desc: 'Whether the add-on is a trial'
                  optional :new_subscription, type: Boolean, desc: 'Whether add-on purchase is for a new subscription'
                end
              end

              params do
                requires :add_on_purchases, type: Hash, desc: 'Hash of add-on names to list of purchase details' do
                  optional :duo_core, type: Array, desc: 'List of Duo Core add-on purchases' do
                    use :add_on
                  end
                  optional :duo_pro, type: Array, desc: 'List of Duo Pro add-on purchases' do
                    use :add_on
                  end
                  optional :duo_enterprise, type: Array, desc: 'List of Duo Enterprise add-on purchases' do
                    use :add_on
                  end
                end
              end

              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              post ":id/subscription_add_on_purchases" do
                result = ::GitlabSubscriptions::AddOnPurchases::GitlabCom::ProvisionService.new(
                  @namespace,
                  declared_params[:add_on_purchases]
                ).execute

                add_on_purchases = result[:add_on_purchases]

                if result.success?
                  present add_on_purchases, with: Entities::Internal::GitlabSubscriptions::AddOnPurchase
                elsif !add_on_purchases || add_on_purchases.empty?
                  bad_request!(result[:message])
                else
                  render_validation_error!(result[:add_on_purchases])
                end
              end

              desc 'Return an add-on purchase for the namespace' do
                detail 'Get the add-on purchase record for the given namespace and add-on'
                success Entities::Internal::GitlabSubscriptions::AddOnPurchase
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
              end
              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              get ":id/subscription_add_on_purchases/:add_on_name" do
                add_on_purchase = find_subscription_add_on_purchase!(@namespace, @add_on)

                present add_on_purchase, with: Entities::Internal::GitlabSubscriptions::AddOnPurchase
              end
            end
          end
        end
      end
    end
  end
end
