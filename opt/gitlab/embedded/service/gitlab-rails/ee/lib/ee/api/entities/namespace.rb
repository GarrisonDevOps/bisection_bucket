# frozen_string_literal: true

module EE
  module API
    module Entities
      module Namespace
        extend ActiveSupport::Concern

        prepended do
          can_update_limits = ->(namespace, opts) { ::Ability.allowed?(opts[:current_user], :update_subscription_limit, namespace) }
          can_admin_namespace = ->(namespace, opts) { ::Ability.allowed?(opts[:current_user], :admin_namespace, namespace) }
          has_gitlab_subscription = ->(namespace) { namespace.gitlab_subscription.present? }
          can_read_usage = ->(namespace, opts) do
            namespace.root? && ::Ability.allowed?(opts[:current_user], :read_compute_minutes, namespace)
          end

          expose :shared_runners_minutes_limit,
            documentation: {
              type: 'Integer', example: 133,
              desc: 'Monthly compute minutes quota allocated to the namespace. Returned only on GitLab.com, ' \
                'for administrators.'
            }, if: can_update_limits
          expose :ci_minutes_usage,
            using: ::API::Entities::Ci::Minutes::Usage,
            documentation: {
              type: '::API::Entities::Ci::Minutes::Usage',
              desc: 'Compute minutes usage breakdown. Returned only for top-level namespaces when the user has the ' \
                'Owner role, is an auditor, or is an administrator. ' \
                '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/12379) in GitLab 19.4.'
            },
            if: can_read_usage do |namespace, options|
            totals = options[:ci_minutes_totals]
            total = totals ? totals.fetch(namespace.id, 0).to_i : nil

            ::Ci::Minutes::Usage.new(namespace, total_minutes_used: total)
          end
          expose :extra_shared_runners_minutes_limit,
            documentation: {
              type: 'Integer', example: 133,
              desc: 'Additional compute minutes added on top of the monthly quota, from purchased minute packs. ' \
                'Returned only on GitLab.com, for administrators.'
            }, if: can_update_limits
          expose :additional_purchased_storage_size, documentation: { type: 'Integer', example: 1000 }, if: can_update_limits
          expose :additional_purchased_storage_ends_on, documentation: { type: 'Date', example: '2022-06-18' }, if: can_update_limits
          expose :billable_members_count,
            documentation: {
              type: 'Integer', example: 2,
              desc: 'Number of billable members in the namespace. `null` unless the user has the Owner role, ' \
                'is an auditor, or is an administrator.'
            } do |namespace, options|
            next unless can_read_billing?(namespace, options)
            next if skip_billable_members_count?(namespace, options)

            namespace.billable_members_count(options[:requested_hosted_plan])
          end
          expose :seats_in_use,
            documentation: {
              type: 'Integer', example: 5,
              desc: 'Number of seats currently in use. Returned only for namespaces with a subscription. ' \
                '`null` unless the user has the Owner role, is an auditor, or is an administrator.'
            }, if: has_gitlab_subscription do |namespace, options|
            next unless can_read_billing?(namespace, options)

            namespace.gitlab_subscription.seats_in_use
          end
          expose :max_seats_used,
            documentation: {
              type: 'Integer', example: 100,
              desc: 'Maximum number of seats used during the current subscription period. Returned only for ' \
                'namespaces with a subscription. `null` unless the user has the Owner role, is an auditor, or is ' \
                'an administrator.'
            }, if: has_gitlab_subscription do |namespace, options|
            next unless can_read_billing?(namespace, options)

            namespace.gitlab_subscription.max_seats_used
          end
          expose :max_seats_used_changed_at,
            documentation: {
              type: 'DateTime', example: '2025-05-15T12:00:02.000Z',
              desc: 'Timestamp of when `max_seats_used` last changed. Returned only for namespaces with a ' \
                'subscription. `null` unless the user has the Owner role, is an auditor, or is an administrator.'
            }, if: has_gitlab_subscription do |namespace, options|
            next unless can_read_billing?(namespace, options)

            namespace.gitlab_subscription.max_seats_used_changed_at
          end
          expose :end_date,
            documentation: {
              type: 'Date', example: '2022-06-18',
              desc: 'End date of the current subscription. Returned only for namespaces with a subscription. ' \
                '`null` if not applicable, or unless the user has the Owner role, is an auditor, or is an administrator.'
            }, if: has_gitlab_subscription do |namespace, options|
            next unless can_read_billing?(namespace, options)

            namespace.gitlab_subscription.end_date
          end
          expose :plan,
            documentation: {
              type: 'String', example: 'default',
              desc: 'Subscription plan of the namespace, for example `free` or `ultimate`. Returned only when the ' \
                'user has the Owner role or is an administrator.'
            }, if: can_admin_namespace do |namespace, _|
            namespace.actual_plan_name
          end
          expose :trial_ends_on,
            documentation: {
              type: 'Date', example: '2022-06-18',
              desc: 'Date the trial ends. `null` if not on a trial. Returned only when the user has the Owner role ' \
                'or is an administrator.'
            }, if: can_admin_namespace do |namespace, _|
            namespace.trial_ends_on
          end
          expose :trial,
            documentation: {
              type: 'Boolean',
              desc: 'If `true`, the namespace is on a trial plan. Returned only when the user has the Owner role ' \
                'or is an administrator.'
            }, if: can_admin_namespace do |namespace, _|
            namespace.trial?
          end

          private

          def can_read_billing?(namespace, opts)
            ::Ability.allowed?(opts[:current_user], :read_billing, namespace)
          end

          def skip_billable_members_count?(namespace, opts)
            namespace.subgroup? && ::Feature.enabled?(:skip_subgroup_billable_members_count, opts[:current_user])
          end
        end
      end
    end
  end
end
