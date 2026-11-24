# frozen_string_literal: true

module EE
  module WorkItems
    module TypesFramework
      module NamespacedType
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :enabled_by_default_for_new_namespaces?
        def enabled_by_default_for_new_namespaces?
          defaults_map.fetch(persistable_id, true)
        end

        private

        def defaults_map
          return {} unless namespace

          ::Gitlab::SafeRequestStore.fetch(defaults_cache_key) do
            settings = ::WorkItems::Settings.for_namespace(namespace)
            if settings&.customizable_type_visibility
              ::WorkItems::TypesFramework::VisibilityDefault.defaults_for_settings(settings)
            else
              {}
            end
          end
        end

        def defaults_cache_key
          scope_id = if namespace.is_a?(::Organizations::Organization)
                       "org:#{namespace.id}"
                     else
                       "ns:#{namespace.root_ancestor&.id || namespace.id}"
                     end

          "wi_type_defaults:#{scope_id}"
        end
      end
    end
  end
end
