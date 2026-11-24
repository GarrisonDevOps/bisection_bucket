# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class CascadeSyncFoundationalFlowsWorker
        include ApplicationWorker

        BATCH_SIZE = 100

        data_consistency :delayed
        feature_category :ai_abstraction_layer
        urgency :low
        worker_has_external_dependencies!
        idempotent!
        concurrency_limit -> { 10 }
        defer_on_database_health_signal :gitlab_main,
          [:namespace_settings, :project_settings, :namespaces, :projects],
          1.minute

        def perform(group_id, user_id = nil, _flow_references = nil)
          # Query count seems to grow with the number of foundational flows
          # and is worth revisiting for optimization.
          # See https://gitlab.com/gitlab-org/gitlab/-/issues/598945.
          Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/598945', new_threshold: 220)

          group = Group.find_by_id(group_id)
          return unless group

          user = user_id ? User.find_by_id(user_id) : nil

          seed_foundational_flows

          sync_groups(group, user)

          sync_projects_optimized(group, user)
        end

        private

        def seed_foundational_flows
          ::Ai::Catalog::Flows::SeedFoundationalFlowsService.new.execute
        end

        def project_namespace_iterator(group)
          cursor = { current_id: group.id, depth: [group.id] }
          Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespaces::ProjectNamespace, cursor: cursor)
        end

        def sync_groups(group, user)
          ::Ai::Catalog::Flows::SyncFoundationalFlowsService.new(
            group,
            current_user: user
          ).execute
        end

        def sync_projects_optimized(group, user)
          return unless user

          foundational_item_ids = Item.foundational_flow_ids
          parent_consumers = fetch_parent_consumers(group)
          catalog_items = fetch_catalog_items
          flow_triggers_by_item = build_flow_triggers_map(catalog_items)

          project_namespace_iterator(group).each_batch(of: BATCH_SIZE) do |project_namespace_ids|
            projects = Project
              .by_project_namespace(project_namespace_ids)
              .with_project_setting
              .with_enabled_foundational_flow_records

            projects.each do |project|
              unless project.project_setting&.duo_foundational_flows_enabled
                project.remove_foundational_flow_consumers(foundational_item_ids)
                next
              end
            end

            next if parent_consumers.empty? || catalog_items.empty?

            ::Ai::Catalog::Flows::SyncBatchFoundationalFlowsService.new(
              projects,
              parent_consumers: parent_consumers,
              catalog_items: catalog_items,
              flow_triggers_by_item: flow_triggers_by_item,
              current_user: user
            ).execute
          end
        end

        def fetch_parent_consumers(group)
          target_ids = group.enabled_flow_catalog_item_ids
          return {} if target_ids.empty?

          group.root_ancestor.configured_ai_catalog_items
            .direct
            .for_catalog_items(target_ids)
            .with_service_account
            .index_by(&:ai_catalog_item_id)
        end

        def fetch_catalog_items
          Item.with_ids(Item.foundational_flow_ids).index_by(&:id)
        end

        def build_flow_triggers_map(catalog_items)
          catalog_items.transform_values do |item|
            item.foundational_flow&.triggers
          end.compact
        end
      end
    end
  end
end
