# frozen_string_literal: true

module Ai
  module Catalog
    module FoundationalFlows
      class SyncService
        include Gitlab::Utils::StrongMemoize

        def initialize(container:, target_ids:)
          @container = container
          @target_ids = Array(target_ids).uniq
        end

        def execute
          if target_ids.empty?
            delete_all_flows
          else
            sync_flows
          end

          ServiceResponse.success
        rescue ActiveRecord::RecordInvalid => e
          ::Gitlab::ErrorTracking.track_exception(
            e,
            **error_tracking_context(e)
          )
          ServiceResponse.error(message: e.message)
        end

        private

        attr_reader :container, :target_ids

        def delete_all_flows
          scoped_flow_records.delete_all
        end

        def sync_flows
          delete_obsolete_flows
          insert_new_flows
        end

        def delete_obsolete_flows
          scoped_flow_records
            .excluding_catalog_items(target_ids)
            .delete_all
        end

        def insert_new_flows
          new_catalog_item_ids = target_ids - existing_catalog_item_ids
          return if new_catalog_item_ids.empty?

          current_time = Time.current
          records = new_catalog_item_ids.map do |catalog_item_id|
            build_flow_record(catalog_item_id, current_time)
          end

          Ai::Catalog::EnabledFoundationalFlow.bulk_insert!(
            records,
            unique_by: unique_constraint
          )
        end

        def existing_catalog_item_ids
          scoped_flow_records.limited_catalog_item_ids
        end

        def scoped_flow_records
          if container.is_a?(Project)
            flow_records.for_project(container.id)
          else
            flow_records.for_namespace(container.id)
          end
        end
        strong_memoize_attr :scoped_flow_records

        def build_flow_record(catalog_item_id, current_time)
          Ai::Catalog::EnabledFoundationalFlow.new(
            **container_attributes,
            catalog_item_id: catalog_item_id,
            created_at: current_time,
            updated_at: current_time
          )
        end

        def flow_records
          container.enabled_foundational_flow_records
        end

        def container_attributes
          if container.is_a?(Project)
            { project_id: container.id, namespace_id: nil }
          else
            { namespace_id: container.id, project_id: nil }
          end
        end

        def unique_constraint
          if container.is_a?(Project)
            [:project_id, :catalog_item_id]
          else
            [:namespace_id, :catalog_item_id]
          end
        end

        def error_tracking_context(exception)
          context = {
            target_ids: target_ids,
            validation_errors: exception.record&.errors&.full_messages&.join(', ')
          }

          if container.is_a?(Project)
            context[:project_id] = container.id
          else
            context[:namespace_id] = container.id
          end

          context
        end
      end
    end
  end
end
