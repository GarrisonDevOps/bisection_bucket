# frozen_string_literal: true

module WorkItems
  module Widgets
    module Statuses
      class TransferLifecycleService
        def initialize(old_root_namespace:, new_root_namespace:)
          @old_root_namespace = old_root_namespace
          @new_root_namespace = new_root_namespace
        end

        def execute
          return unless old_root_namespace && new_root_namespace
          return if old_root_namespace == new_root_namespace

          # we only need to copy custom lifecycles for this transfer process
          old_lifecycles = old_root_namespace.custom_lifecycles
          new_lifecycles = new_root_namespace.custom_lifecycles

          old_lifecycles.each do |old_lifecycle|
            # Direct rows only: a type masked to a lifecycle (epic) must not be
            # copied or matched, so it stays masked in the new root namespace.
            new_lifecycle = new_lifecycles.find do |lifecycle|
              (old_lifecycle.work_item_type_ids & lifecycle.work_item_type_ids).any?
            end

            # if a custom lifecycle already exists, we do not re-create it
            next if new_lifecycle

            # we need to reload the assocation, as the status can be created in the previous loop.
            existing_statuses = new_root_namespace&.custom_statuses&.reload
            ApplicationRecord.transaction do
              new_statuses = lifecycle_status_attributes(old_lifecycle).map do |attributes|
                status = existing_statuses.find { |s| s.name == attributes[:name] }
                status || WorkItems::Statuses::Custom::Status.create!(attributes)
              end

              WorkItems::Statuses::Custom::Lifecycle.create!(lifecycle_arguments(old_lifecycle, new_statuses))
            end
          end
        end

        private

        attr_reader :old_root_namespace, :new_root_namespace

        def lifecycle_arguments(old_lifecycle, new_statuses)
          {
            namespace_id: new_root_namespace.id,
            statuses: new_statuses,
            name: old_lifecycle.name,
            created_by: old_lifecycle.created_by,
            work_item_type_ids: old_lifecycle.work_item_type_ids,
            default_open_status: find_default_status_for(old_lifecycle.default_open_status, new_statuses),
            default_closed_status: find_default_status_for(old_lifecycle.default_closed_status, new_statuses),
            default_duplicate_status: find_default_status_for(old_lifecycle.default_duplicate_status, new_statuses)
          }
        end

        def lifecycle_status_attributes(old_lifecycle)
          old_lifecycle.statuses.map do |status|
            status_attributes(status)
          end
        end

        def status_attributes(status)
          {
            name: status.name,
            category: status.category,
            description: status.description,
            color: status.color,
            created_by_id: status.created_by_id,
            converted_from_system_defined_status_identifier: status.converted_from_system_defined_status_identifier,
            namespace_id: new_root_namespace.id
          }
        end

        def find_default_status_for(old_default_status, new_statuses)
          new_statuses.find { |status| status.name == old_default_status.name }
        end
      end
    end
  end
end
