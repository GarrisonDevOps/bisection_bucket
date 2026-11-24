# frozen_string_literal: true

module WorkItems
  module TypesFramework
    class SeedVisibilityDefaultsService
      def initialize(namespace)
        @namespace = namespace
      end

      def execute
        settings = ::WorkItems::Settings.for_namespace(@namespace)
        return unless settings&.customizable_type_visibility

        defaults_map = ::WorkItems::TypesFramework::VisibilityDefault
          .for_settings(settings)
          .index_by(&:work_item_type_id)
        resolved_visibility = ::WorkItems::TypesFramework::Visibility.resolve_for_namespace(@namespace)

        type_ids = (defaults_map.keys | resolved_visibility.keys)
        return if type_ids.empty?

        type_ids.each do |type_id|
          default_enabled = defaults_map[type_id]&.enabled
          default_enabled = true if default_enabled.nil?
          resolved = resolved_visibility.fetch(type_id, true)
          next if default_enabled == resolved

          ::WorkItems::TypesFramework::Visibility.create!(
            namespace: @namespace,
            work_item_type_id: type_id,
            enabled: default_enabled,
            propagate: false
          )
        end
      end
    end
  end
end
