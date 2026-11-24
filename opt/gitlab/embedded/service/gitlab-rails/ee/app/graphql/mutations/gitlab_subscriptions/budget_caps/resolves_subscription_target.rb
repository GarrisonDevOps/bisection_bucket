# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module BudgetCaps
      module ResolvesSubscriptionTarget
        extend ActiveSupport::Concern
        include ::GitlabSubscriptions::UsageRateLimitable

        BUDGET_CAP_RATE_LIMIT_KEYS = %i[
          budget_cap_update_per_minute
          budget_cap_update_per_hour
          budget_cap_update_per_day
        ].freeze

        SubscriptionTarget = Data.define(:type, :namespace, :organization) do
          def initialize(type:, namespace: nil, organization: nil)
            super
          end

          def instance?
            type == :instance
          end
        end

        private

        def usage_rate_limit_keys
          BUDGET_CAP_RATE_LIMIT_KEYS
        end

        def usage_rate_limit_enforced?(namespace)
          ::Feature.enabled?(:enforce_budget_cap_rate_limits, namespace, type: :gitlab_com_derisk)
        end

        def usage_rate_limit_log_message
          'Budget cap rate limit exceeded'
        end

        def resolve_target(namespace_path, organization_id = nil)
          return resolve_organization_target(organization_id) if organization_id

          if namespace_path
            namespace = ::Namespace.find_by_full_path(namespace_path)
            raise_resource_not_available_error! unless namespace
            raise_resource_not_available_error! unless namespace.root? && namespace.group_namespace?

            SubscriptionTarget.new(type: :namespace, namespace: namespace)
          else
            SubscriptionTarget.new(type: :instance)
          end
        end

        def resolve_organization_target(organization_id)
          organization = ::Organizations::Organization.find_by_id(organization_id)
          raise_resource_not_available_error! unless organization

          namespace = organization.billing_namespace
          raise_resource_not_available_error! unless namespace&.root? && namespace.group_namespace?
          raise_resource_not_available_error! unless namespace.organization_id == organization.id

          SubscriptionTarget.new(type: :namespace, namespace: namespace, organization: organization)
        end

        def authorize_mutation!(target)
          allowed = if target.organization
                      Ability.allowed?(
                        current_user, :update_subscription_usage_cap, target.organization
                      )
                    elsif target.instance?
                      Ability.allowed?(
                        current_user, :update_subscription_usage_cap
                      )
                    else
                      Ability.allowed?(
                        current_user, :update_subscription_usage_cap, target.namespace
                      )
                    end

          raise_resource_not_available_error! unless allowed
        end

        def build_subscription_usage_client(target)
          if target.instance?
            billable_license = License.billable_license || License.current
            raise_resource_not_available_error! unless billable_license

            license_key = billable_license.data
          end

          ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(
            license_key: license_key,
            namespace_id: target.namespace&.id
          )
        end
      end
    end
  end
end
