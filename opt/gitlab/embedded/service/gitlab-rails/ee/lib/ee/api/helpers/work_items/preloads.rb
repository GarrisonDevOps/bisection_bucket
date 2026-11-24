# frozen_string_literal: true

module EE
  module API
    module Helpers
      module WorkItems
        module Preloads
          extend ::Gitlab::Utils::Override

          # Covers both serializing the sourcing records and their read_work_item / read_milestone checks
          SOURCING_WORK_ITEM_PRELOADS = (
            ::API::Helpers::WorkItems::Preloads::WORK_ITEM_REFERENCE_PRELOADS +
            ::API::Helpers::WorkItems::Preloads::WORK_ITEM_POLICY_PRELOADS +
            [{ namespace: :route }]
          ).freeze
          SOURCING_MILESTONE_PRELOADS = [
            { group: :route },
            { project: [:project_feature, { namespace: :route }] }
          ].freeze

          EE_FEATURE_PRELOADS = {
            agent_plan: [:agent_plan, :assignees],
            health_status: [],
            color: [:color],
            progress: [:progress],
            iteration: [{ iteration: :group }],
            status: [{ current_status: :custom_status }],
            weight: [:weights_source],
            custom_fields: [
              :namespace,
              :text_field_values,
              :number_field_values,
              :date_field_values,
              { select_field_values: :custom_field_select_option }
            ],
            start_and_due_date: [
              {
                dates_source: {
                  start_date_sourcing_work_item: SOURCING_WORK_ITEM_PRELOADS,
                  due_date_sourcing_work_item: SOURCING_WORK_ITEM_PRELOADS,
                  start_date_sourcing_milestone: SOURCING_MILESTONE_PRELOADS,
                  due_date_sourcing_milestone: SOURCING_MILESTONE_PRELOADS
                }
              }
            ]
          }.freeze

          override :preload_associations_for
          def preload_associations_for(field_keys, feature_keys, resource_parent)
            preloads = super

            ee_preloads = feature_keys.flat_map do |feature|
              EE_FEATURE_PRELOADS.fetch(feature, [])
            end

            (preloads + ee_preloads).uniq
          end

          override :preload_feature_authorization
          def preload_feature_authorization(work_items, feature_keys)
            super
            preload_dates_sourcing_authorization(work_items, feature_keys)
          end

          override :count_preloads_for
          def count_preloads_for(work_items, field_keys, feature_keys)
            preloads = super
            preloads[:blocked_by_counts] = preload_blocked_by_counts(work_items) if feature_keys.include?(:linked_items)
            preloads
          end

          private

          def preload_dates_sourcing_authorization(work_items, feature_keys)
            return unless current_user
            return unless feature_keys.include?(:start_and_due_date)

            dates_sources = work_items.filter_map(&:dates_source)
            sourcing_work_items = dates_sources.flat_map do |source|
              [source.start_date_sourcing_work_item, source.due_date_sourcing_work_item]
            end.compact.uniq
            sourcing_milestones = dates_sources.flat_map do |source|
              [source.start_date_sourcing_milestone, source.due_date_sourcing_milestone]
            end.compact.uniq

            if sourcing_work_items.any?
              # The work item type lookup in the policy resolves the project from the namespace, not the work item
              project_namespaces = sourcing_work_items.map(&:namespace).grep(::Namespaces::ProjectNamespace)
              ::ActiveRecord::Associations::Preloader.new(records: project_namespaces, associations: :project).call

              preload_policies_for(sourcing_work_items)
            end

            milestone_projects = sourcing_milestones.filter_map(&:project)
            if milestone_projects.any?
              ::Preloaders::UserMaxAccessLevelInProjectsPreloader.new(milestone_projects, current_user).execute
            end

            milestone_groups = sourcing_milestones.filter_map(&:group)
            ::Preloaders::GroupPolicyPreloader.new(milestone_groups, current_user).execute if milestone_groups.any?
          end

          def preload_blocked_by_counts(work_items)
            return {} if work_items.empty?

            ::WorkItems::RelatedWorkItemLink
              .blocked_issuables_for_collection(work_items.map(&:id))
              .each_with_object({}) { |row, hash| hash[row.blocked_issue_id] = row.count.to_i }
          end
        end
      end
    end
  end
end
