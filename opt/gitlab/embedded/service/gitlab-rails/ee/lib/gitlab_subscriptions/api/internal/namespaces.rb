# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class Namespaces < ::API::Base
        feature_category :plan_provisioning
        urgency :low

        namespace :internal do
          namespace :gitlab_subscriptions do
            resource :namespaces do
              helpers do
                params :gitlab_subscription_optional_attributes do
                  optional :start_date, type: Date, desc: 'Start date of subscription'
                  optional :seats, type: Integer, desc: 'Number of seats in subscription'
                  optional :max_seats_used, type: Integer, desc: 'Highest number of active users in the last month'
                  optional :plan_code, type: String, desc: 'Subscription tier code'
                  optional :end_date, type: Date, desc: 'End date of subscription'
                  optional :auto_renew, type: Grape::API::Boolean, desc: 'Subscription will auto renew on end date'
                  optional :trial, type: Grape::API::Boolean, desc: 'Subscription is a trial'
                  optional :trial_ends_on, type: Date, desc: 'End date of trial'
                  optional :trial_starts_on, type: Date, desc: 'Start date of trial'
                  optional :trial_extension_type, type: Integer, desc: 'Subscription is an extended/reactivated trial'
                end

                def update_namespace(namespace)
                  update_attrs = declared_params(include_missing: false)

                  # Reset last_ci_minutes_notification_at if customer purchased extra compute minutes.
                  if params[:extra_shared_runners_minutes_limit].present?
                    update_attrs[:last_ci_minutes_notification_at] = nil
                    update_attrs[:last_ci_minutes_usage_notification_level] = nil

                    ::Ci::Runner.instance_type.each(&:tick_runner_queue)
                  end

                  namespace.update(update_attrs).tap do
                    if update_attrs[:extra_shared_runners_minutes_limit].present? ||
                        update_attrs.key?(:shared_runners_minutes_limit)
                      ::Ci::Minutes::RefreshCachedDataService.new(namespace).execute
                      ::Ci::Minutes::NamespaceMonthlyUsage.reset_current_notification_level(namespace)
                    end
                  end
                end
              end

              desc 'Get namespace by ID' do
                detail 'Returns a namespace by ID.'
                success Entities::Internal::Namespace
                failure [
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
              end
              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              get ':id', requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
                namespace = find_namespace(params[:id])

                not_found!('Namespace') unless namespace.present?

                present namespace, with: Entities::Internal::Namespace
              end

              desc 'Update a namespace by ID' do
                detail "Updates a namespace's compute-minutes quotas, storage purchase information, " \
                  'and GitLab subscription attributes.'
                success Entities::Internal::Namespace
                failure [
                  { code: 401, message: 'Unauthorized' },
                  { code: 404, message: 'Not found' }
                ]
              end
              params do
                optional :shared_runners_minutes_limit, type: Integer, desc: "Compute minutes quota"
                optional :extra_shared_runners_minutes_limit, type: Integer, desc: "Extra compute minutes"
                optional :additional_purchased_storage_size, type: Integer, desc: "Additional storage size"
                optional :additional_purchased_storage_ends_on, type: Date, desc: "Additional purchased storage Ends on"
                optional :gitlab_subscription_attributes, type: Hash, desc: 'GitLab subscription attributes' do
                  use :gitlab_subscription_optional_attributes
                end
              end

              route_setting :authorization, skip_granular_token_authorization: :subscription_portal_jwt_auth
              put ':id', requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
                namespace = find_namespace(params[:id])

                break not_found!('Namespace') unless namespace

                if update_namespace(namespace)
                  present namespace, with: Entities::Internal::Namespace
                else
                  render_validation_error!(namespace)
                end
              end
            end
          end
        end
      end
    end
  end
end
