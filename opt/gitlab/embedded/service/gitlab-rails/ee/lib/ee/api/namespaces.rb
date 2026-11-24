# frozen_string_literal: true

module EE
  module API
    module Namespaces
      extend ActiveSupport::Concern

      prepended do
        helpers ::GitlabSubscriptions::BilledUsersScanRateLimit

        helpers do
          extend ::Gitlab::Utils::Override

          params :optional_list_params_ee do
            # Used only by GitLab.com
            optional :requested_hosted_plan, type: String, desc: 'Name of the hosted plan requested by the customer.'
          end

          override :custom_namespace_present_options
          def custom_namespace_present_options(namespaces = nil)
            options = { requested_hosted_plan: params[:requested_hosted_plan] }
            options[:ci_minutes_totals] = ci_minutes_totals_for(namespaces) if namespaces
            options
          end

          def ci_minutes_totals_for(namespaces)
            root_ids = namespaces.filter_map { |ns| ns.id if ns.root? }
            return {} if root_ids.empty?

            ::Ci::Minutes::NamespaceMonthlyUsage.totals_for_namespaces(root_ids)
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
              if update_attrs[:extra_shared_runners_minutes_limit].present? || update_attrs.key?(:shared_runners_minutes_limit)
                ::Ci::Minutes::RefreshCachedDataService.new(namespace).execute
                ::Ci::Minutes::NamespaceMonthlyUsage.reset_current_notification_level(namespace)
              end
            end
          end
        end

        resource :namespaces, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          helpers do
            params :gitlab_subscription_optional_attributes do
              optional :start_date, type: Date, desc: 'Start date of the subscription.'
              optional :seats, type: Integer, desc: 'Number of seats in the subscription.'
              optional :max_seats_used, type: Integer, desc: 'Highest number of active users in the last month.'
              optional :plan_code, type: String, desc: 'Subscription tier code.'
              optional :end_date, type: Date, desc: 'End date of the subscription.'
              optional :auto_renew, type: Grape::API::Boolean, desc: 'If `true`, the subscription renews automatically on the end date.'
              optional :trial, type: Grape::API::Boolean, desc: 'If `true`, the subscription is a trial.'
              optional :trial_ends_on, type: Date, desc: 'End date of the trial.'
              optional :trial_starts_on, type: Date, desc: 'Start date of the trial.'
              optional :trial_extension_type, type: Integer, desc: 'Type of trial extension applied to the subscription. `1` means extended, `2` means reactivated.'
            end
          end

          desc 'Update a namespace' do
            detail 'Deprecated in 17.8'
            success ::API::Entities::Namespace
            tags %w[namespaces]
          end
          params do
            optional :shared_runners_minutes_limit, type: Integer, desc: 'Compute minutes quota for the namespace.'
            optional :extra_shared_runners_minutes_limit, type: Integer, desc: 'Extra compute minutes quota for the namespace.'
            optional :additional_purchased_storage_size, type: Integer, desc: 'Additional storage size purchased for the namespace.'
            optional :additional_purchased_storage_ends_on, type: Date, desc: 'End of subscription of the additional purchased storage.'
            optional :gitlab_subscription_attributes, type: Hash, desc: 'Object that contains information on the GitLab subscription.' do
              use :gitlab_subscription_optional_attributes
            end
          end
          route_setting :authorization, permissions: :update_namespace, boundary_type: :instance,
            assignable_when: [:admin]
          put ':id', feature_category: :groups_and_projects, urgency: :low do
            authenticated_as_admin!

            namespace = find_namespace(params[:id])

            break not_found!('Namespace') unless namespace

            if update_namespace(namespace)
              present namespace, with: ::API::Entities::Namespace, current_user: current_user
            else
              render_validation_error!(namespace)
            end
          end

          desc 'Retrieve namespace subscription' do
            detail 'Retrieves GitLab subscription details for a specified namespace.'
            success ::API::Entities::GitlabSubscription
            tags %w[namespaces]
          end
          route_setting :authorization,
            permissions: :read_gitlab_subscription,
            boundaries: [
              { boundary_type: :group },
              { boundary_type: :user }
            ]
          get ":id/gitlab_subscription", urgency: :low, feature_category: :subscription_management do
            if current_user.auditor?
              namespace = find_namespace(params[:id])

              authorize! :read_billing, namespace
            else
              namespace = find_namespace!(params[:id])
              authorize! :admin_namespace, namespace
            end

            subscription = namespace.gitlab_subscription

            if namespace.group_namespace? && subscription && !subscription.has_a_paid_hosted_plan?
              check_billed_users_scan_rate_limit!(namespace)
            end

            present subscription || {}, with: ::API::Entities::GitlabSubscription
          end

          desc 'Creates a storage limit exclusion for a Namespace' do
            detail 'Creates a Namespaces::Storage::LimitExclusion'
            success code: 201, model: ::API::Entities::Namespaces::Storage::LimitExclusion
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' }
            ]
            tags %w[namespaces]
          end
          params do
            requires :reason, type: String, desc: 'Reason the namespace is being excluded.'
          end
          route_setting :authorization, permissions: :create_namespace_storage_limit_exclusion,
            boundary_type: :instance,
            assignable_when: [:admin, :saas]
          post ':id/storage/limit_exclusion', feature_category: :consumables_cost_management do
            authenticated_as_admin!

            unless ::Gitlab::Saas.feature_available?(:namespaces_storage_limit)
              forbidden!('this API is for GitLab.com only')
            end

            namespace = find_namespace!(params[:id])

            bad_request!('must use a root namespace') unless namespace.root?
            bad_request!('already excluded') if namespace.storage_limit_exclusion

            limit_exclusion = namespace.build_storage_limit_exclusion(
              reason: params[:reason]
            )

            if limit_exclusion.save
              present limit_exclusion, with: ::API::Entities::Namespaces::Storage::LimitExclusion
            else
              render_validation_error!(limit_exclusion)
            end
          end

          desc 'Removes a storage limit exclusion for a Namespace' do
            detail 'Removes a Namespaces::Storage::LimitExclusion'
            success code: 204
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 422, message: 'Unprocessable entity' }
            ]
            tags %w[namespaces]
          end
          route_setting :authorization, permissions: :delete_namespace_storage_limit_exclusion,
            boundary_type: :instance,
            assignable_when: [:admin, :saas]
          delete ':id/storage/limit_exclusion' do
            authenticated_as_admin!

            unless ::Gitlab::Saas.feature_available?(:namespaces_storage_limit)
              forbidden!('this API is for GitLab.com only')
            end

            namespace = find_namespace!(params[:id])

            bad_request!('must use a root namespace') unless namespace.root?
            bad_request!('not excluded') unless namespace.storage_limit_exclusion

            if namespace.storage_limit_exclusion.destroy
              no_content!
            else
              unprocessable_entity!('Exclusion could not be removed')
            end
          end

          desc 'Retrieve all limit exclusions' do
            detail 'Gets all records for namespaces that have been excluded'
            success code: 200, model: ::API::Entities::Namespaces::Storage::LimitExclusion
            is_array true
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' }
            ]
            tags %w[namespaces]
          end
          params do
            use :pagination
          end
          route_setting :authorization, permissions: :read_namespace_storage_limit_exclusion,
            boundary_type: :instance,
            assignable_when: [:admin, :saas]
          get 'storage/limit_exclusions', feature_category: :consumables_cost_management do
            authenticated_as_admin!

            unless ::Gitlab::Saas.feature_available?(:namespaces_storage_limit)
              forbidden!('this API is for GitLab.com only')
            end

            exclusions = ::Namespaces::Storage::LimitExclusion.all

            present paginate(exclusions), with: ::API::Entities::Namespaces::Storage::LimitExclusion
          end
        end
      end
    end
  end
end
