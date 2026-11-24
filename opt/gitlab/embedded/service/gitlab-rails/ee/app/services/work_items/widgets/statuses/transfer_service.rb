# frozen_string_literal: true

module WorkItems
  module Widgets
    module Statuses
      class TransferService
        def initialize(old_root_namespace:, new_root_namespace:, project_namespace_ids:)
          @old_root_namespace = old_root_namespace
          @new_root_namespace = new_root_namespace
          @project_namespace_ids = Array(project_namespace_ids)
        end

        def execute
          return if old_root_namespace == new_root_namespace

          old_lifecycles = old_root_namespace&.lifecycles
          new_lifecycles = new_root_namespace&.lifecycles

          return unless old_lifecycles && new_lifecycles

          old_lifecycles.each do |old_lifecycle|
            new_lifecycle = new_lifecycles.find do |lifecycle|
              (old_lifecycle.work_item_types(old_root_namespace) & lifecycle.work_item_types(new_root_namespace)).any?
            end

            next if new_lifecycle.nil? || old_lifecycle == new_lifecycle

            status_mapping = status_mapping(old_lifecycle, new_lifecycle)

            BulkStatusUpdater.new(status_mapping, old_lifecycle, project_namespace_ids).execute
          end
        end

        private

        attr_reader :old_root_namespace, :new_root_namespace, :project_namespace_ids

        def status_mapping(old_lifecycle, new_lifecycle)
          old_lifecycle&.statuses&.index_with do |status|
            StatusMatcherService.new(status, new_lifecycle).find_fallback
          end
        end
      end
    end
  end
end
