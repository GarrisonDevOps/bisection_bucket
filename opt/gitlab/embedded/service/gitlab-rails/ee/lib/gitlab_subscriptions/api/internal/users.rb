# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class Users < ::API::Base
        feature_category :subscription_management
        urgency :low

        namespace :internal do
          namespace :gitlab_subscriptions do
            resource :users do
              desc 'Retrieve a single user' do
                detail 'Retrieves a single user. Used by the Customers Portal.'
                success Entities::Internal::User
              end

              params do
                requires :id, type: Integer, desc: 'The ID of the user'
              end

              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              get ':id' do
                user = User.find_by_id(params[:id])

                not_found!('User') unless user

                present user, with: Entities::Internal::User
              end

              desc 'Update the credit card validation for a user' do
                detail 'Updates the credit card validation record for a specified user. Used by the Customers Portal.'
                success ::API::Entities::BasicSuccess
              end
              params do
                requires :user_id, type: String, desc: 'The ID or username of the user'
                requires :credit_card_validated_at, type: DateTime, desc: 'The time when the credit card was validated'
                requires :credit_card_expiration_month, type: Integer, desc: 'The month the credit card expires'
                requires :credit_card_expiration_year, type: Integer, desc: 'The year the credit card expires'
                requires :credit_card_holder_name, type: String, desc: 'The credit card holder name'
                requires :credit_card_mask_number, type: String, desc: 'The last 4 digits of credit card number'
                requires :credit_card_type, type: String, desc: 'The credit card network name'

                optional :zuora_payment_method_xid, type: String, desc: 'The Zuora payment method ID'
                optional :stripe_setup_intent_xid, type: String, desc: 'The Stripe setup intent ID'
                optional :stripe_payment_method_xid, type: String, desc: 'The Stripe payment method ID'
                optional :stripe_card_fingerprint, type: String, desc: 'The Stripe credit card fingerprint'
              end

              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              put ":user_id/credit_card_validation", urgency: :low, feature_category: :subscription_management do
                user = find_user(params[:user_id])
                not_found!('User') unless user

                attrs = declared_params(include_missing: false)

                service = ::Users::UpsertCreditCardValidationService.new(attrs).execute

                if service.success?
                  present user.credit_card_validation, with: ::API::Entities::BasicSuccess
                else
                  bad_request!
                end
              end
            end

            resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
              before do
                @namespace = find_namespace(params[:namespace_id])

                not_found!('Namespace') unless @namespace.present?
              end

              desc 'Retrieve user permissions' do
                detail 'Retrieves the permissions for a specified user in a namespace. Used by the Customers Portal.'
                success Entities::Internal::Namespaces::UserPermissions
              end
              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              get ":namespace_id/user_permissions/:user_id" do
                user = User.find_by_id(params[:user_id])

                not_found!('User') unless user.present?

                present :edit_billing, Ability.allowed?(user, :edit_billing, @namespace)
              end
            end
          end
        end
      end
    end
  end
end
