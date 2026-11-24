# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class Namespace < ::API::Entities::NamespaceBasic
          has_gitlab_subscription = ->(namespace) { namespace.gitlab_subscription.present? }
          namespace_for_group = ->(namespace) { namespace.kind == 'group' }

          expose :shared_runners_minutes_limit, documentation: { type: 'Integer', example: 133 }
          expose :extra_shared_runners_minutes_limit, documentation: { type: 'Integer', example: 133 }
          expose :additional_purchased_storage_size, documentation: { type: 'Integer', example: 1000 }
          expose :additional_purchased_storage_ends_on, documentation: { type: 'Date', example: '2022-06-18' }
          expose :billable_members_count, documentation: { type: 'Integer', example: 2 } do |namespace, options|
            namespace.billable_members_count(options[:requested_hosted_plan])
          end

          expose :seats_in_use, documentation: { type: 'Integer', example: 5 },
            if: has_gitlab_subscription do |namespace, _|
            namespace.gitlab_subscription.seats_in_use
          end

          expose :max_seats_used, documentation: { type: 'Integer', example: 100 },
            if: has_gitlab_subscription do |namespace, _|
            namespace.gitlab_subscription.max_seats_used
          end

          expose :max_seats_used_changed_at, documentation: { type: 'Date', example: '2022-06-18' },
            if: has_gitlab_subscription do |namespace, _|
            namespace.gitlab_subscription.max_seats_used_changed_at
          end

          expose :end_date, documentation: { type: 'Date', example: '2022-06-18' },
            if: has_gitlab_subscription do |namespace, _|
            namespace.gitlab_subscription.end_date
          end

          expose :plan, documentation: { type: 'String', example: 'default' } do |namespace, _|
            namespace.actual_plan_name
          end

          expose :trial_ends_on, documentation: { type: 'Date', example: '2022-06-18' } do |namespace, _|
            namespace.trial_ends_on
          end

          expose :trial, documentation: { type: 'Boolean' } do |namespace, _|
            namespace.trial?
          end

          # rubocop:disable API/EntityFieldType -- the cop only allows ::API::Entities classes; this entity is internal API specific
          expose :organization, using: Organization, documentation: { type: 'Organization' } do |namespace, _|
            namespace.organization unless namespace.organization.default?
          end
          # rubocop:enable API/EntityFieldType

          expose :is_nominated_for_billing, documentation: { type: 'Boolean' } do |namespace, _|
            namespace.gitlab_subscription.present? &&
              namespace.gitlab_subscription.organization_gitlab_subscription.present?
          end

          expose :members_count_with_descendants, documentation: { type: 'Integer', example: 5 },
            if: namespace_for_group do |namespace, _|
            namespace.users_with_descendants.count
          end

          expose :root_repository_size, documentation: { type: 'Integer', example: 123 },
            if: namespace_for_group do |namespace, _|
            namespace.root_storage_statistics&.repository_size
          end

          expose :projects_count, documentation: { type: 'Integer', example: 123 },
            if: namespace_for_group do |namespace, _|
            namespace.all_projects.count
          end
        end
      end
    end
  end
end
