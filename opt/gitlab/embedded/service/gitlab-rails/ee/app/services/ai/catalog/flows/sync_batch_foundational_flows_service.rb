# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class SyncBatchFoundationalFlowsService
        def initialize(projects, parent_consumers:, catalog_items:, flow_triggers_by_item:, current_user:)
          @projects = projects
          @parent_consumers = parent_consumers
          @catalog_items = catalog_items
          @flow_triggers_by_item = flow_triggers_by_item
          @current_user = current_user
          @now = Time.current
        end

        def execute
          projects_to_sync = @projects.select { |p| p.enabled_flow_catalog_item_ids.any? }
          return if projects_to_sync.empty?

          project_ids = projects_to_sync.map(&:id)

          existing_consumers = load_existing_consumers(project_ids)

          members_to_add = []
          consumers_to_insert = []
          project_item_pairs_for_triggers = []

          projects_to_sync.each do |project|
            project.enabled_flow_catalog_item_ids.each do |item_id|
              next if existing_consumers.include?([project.id, item_id])

              parent_consumer = @parent_consumers[item_id]
              next unless parent_consumer

              service_account = parent_consumer.service_account
              next unless service_account
              next unless @catalog_items[item_id]

              members_to_add << { project: project, service_account: service_account }
              consumers_to_insert << build_consumer_attrs(project, item_id, parent_consumer)

              project_item_pairs_for_triggers << [project.id, item_id] if @flow_triggers_by_item[item_id]
            end
          end

          ::Ai::ServiceAccountProjectMemberBulkAddService.new(members_to_add, current_user: @current_user).execute
          inserted_consumers = bulk_insert_consumers(consumers_to_insert)
          bulk_insert_triggers(inserted_consumers, project_item_pairs_for_triggers)
        end

        private

        def load_existing_consumers(project_ids)
          ItemConsumer
            .for_projects(project_ids)
            .for_catalog_items(@catalog_items.keys)
            .pluck(:project_id, :ai_catalog_item_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- batch bounded by BATCH_SIZE
            .to_set
        end

        def build_consumer_attrs(project, item_id, parent_consumer)
          {
            project_id: project.id,
            ai_catalog_item_id: item_id,
            parent_item_consumer_id: parent_consumer.id,
            pinned_version_prefix: parent_consumer.pinned_version_prefix,
            enabled: true,
            locked: true,
            created_at: @now,
            updated_at: @now
          }
        end

        def bulk_insert_consumers(consumers_to_insert)
          return [] if consumers_to_insert.empty?

          ItemConsumer.insert_all(consumers_to_insert, returning: %w[id project_id ai_catalog_item_id])
        end

        def bulk_insert_triggers(inserted_consumers, project_item_pairs_for_triggers)
          return if inserted_consumers.empty? || project_item_pairs_for_triggers.empty?

          consumer_lookup = inserted_consumers.index_by { |row| [row['project_id'], row['ai_catalog_item_id']] }

          triggers_to_insert = []

          project_item_pairs_for_triggers.each do |project_id, item_id|
            consumer_row = consumer_lookup[[project_id, item_id]]
            next unless consumer_row

            item = @catalog_items[item_id]
            event_types = @flow_triggers_by_item[item_id]
            next unless event_types&.any?

            triggers_to_insert << {
              project_id: project_id,
              ai_catalog_item_consumer_id: consumer_row['id'],
              description: "Foundational flow trigger for #{item.name}",
              event_types: event_types,
              # As in SyncFoundationalFlowsService#build_trigger_params: copy the flow's
              # default_trigger_filter onto the trigger.
              filter: item.foundational_flow&.default_trigger_filter || {},
              created_at: @now,
              updated_at: @now
            }
          end

          return unless triggers_to_insert.any?

          result = FlowTrigger.insert_all(triggers_to_insert, returning: %w[id project_id description])
          emit_trigger_audit_events(result)
        end

        def emit_trigger_audit_events(result)
          return unless @current_user

          projects_by_id = @projects.index_by(&:id)

          result.each do |row|
            project = projects_by_id[row['project_id']]
            next unless project

            event_name = 'flow_trigger_created'
            ::Gitlab::Audit::Auditor.audit({
              name: event_name,
              author: @current_user,
              scope: project,
              target: ::Ai::FlowTrigger.new(id: row['id'], description: row['description']),
              target_details: "#{row['description']} (ID: #{row['id']})",
              message: event_name.humanize
            })
          end
        end
      end
    end
  end
end
