# frozen_string_literal: true

module Namespaces
  class CascadeBuiltInProjectTemplatesEnabledService
    INSTANCE_BATCH_SIZE = 500

    def initialize(enabled)
      @enabled = enabled
    end

    def update_namespace_settings(namespace_ids)
      ::NamespaceSetting.for_namespaces(namespace_ids)
        .update_all(built_in_project_templates_enabled: @enabled)
    end

    def update_instance_batch(cursor: 0, limit: INSTANCE_BATCH_SIZE)
      namespace_ids = ::NamespaceSetting.next_namespace_ids(cursor: cursor, limit: limit)

      return if namespace_ids.empty?

      update_namespace_settings(namespace_ids)

      namespace_ids.last
    end
  end
end
