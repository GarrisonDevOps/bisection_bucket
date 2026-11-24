# frozen_string_literal: true

module WorkItems
  module Statuses
    module Lifecycles
      # Single source of truth for resolving the status lifecycle of a work item type
      # in a given namespace.
      #
      # A lifecycle is either an in-code system-defined lifecycle or a database-backed
      # custom lifecycle. The rule is: use the custom lifecycle attached to this type in
      # the namespace if one exists, otherwise fall back to the system-defined lifecycle.
      #
      # Expects a root namespace id. Custom lifecycles are keyed by root namespace, so
      # callers must pass the root namespace id (the id every existing caller already
      # resolves before calling). The custom lifecycles for that namespace are loaded
      # once, indexed by type, and cached in the request store so all types share the
      # same index within a request.
      class Provider
        include ::Gitlab::Utils::StrongMemoize

        def initialize(root_namespace_id)
          @root_namespace_id = root_namespace_id
        end

        def find_by_type(type)
          find_custom_by_type(type) || system_defined_lifecycle_for(type)
        end

        def find_custom_by_type(type)
          return unless root_namespace_id

          # Types that were always status-capable (issue, task) resolve exactly as
          # they did before masking existed: direct row or nothing. Masking and the
          # widget-capability gate apply only to flag-gated types (epic) so that
          # rolling this out changes nothing for existing types.
          return index[type.persistable_id] unless status_flag_gated_type?(type)

          return if index.empty?
          # Flag only, not widget presence: like the system-defined fallback, a missing
          # license must not make the epic diverge from the Issue lifecycle.
          return if status_feature_flag_disabled_for?(type)

          index[type.persistable_id] || masked_lifecycle
        end

        # Materializes the real type<->lifecycle join row for a flag-gated type
        # that is only masked (no direct row) in a custom-lifecycle namespace.
        # Idempotent: a no-op when a direct row already exists or the type is not
        # masked here. Must be called from a write context (status write), never
        # from a read path. Returns true when a row was created (or a concurrent
        # create won the race), false when nothing needed persisting.
        def ensure_connection!(type)
          return false unless root_namespace_id
          return false unless status_flag_gated_type?(type)
          return false if index.empty?
          return false unless type_supports_status?(type)
          return false if index.key?(type.persistable_id)

          ::WorkItems::TypeCustomLifecycle.create!(
            namespace_id: root_namespace_id,
            lifecycle: masked_lifecycle,
            work_item_type_id: type.persistable_id
          )

          bust_index_cache
          true
        rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
          # A concurrent write can land between our index read and the insert; the
          # uniqueness validation then raises RecordInvalid rather than RecordNotUnique.
          bust_index_cache
          raise unless index.key?(type.persistable_id)

          true
        end

        # All types resolving to `lifecycle` in this namespace: the directly
        # attached ones plus any flag-gated type that is only masked to it.
        # Backs the admin type list and mapping generation so a masked type is
        # never left out of a lifecycle mutation.
        def types_for(lifecycle)
          lifecycle.type_custom_lifecycles.map(&:work_item_type) | masked_types_for(lifecycle)
        end

        # The flag-gated types resolving to `lifecycle` only via masking (no
        # direct row). Empty unless `lifecycle` is the active mask target.
        def masked_types_for(lifecycle)
          return [] unless root_namespace_id
          return [] if index.empty?
          return [] unless lifecycle == masked_lifecycle

          masked_types
        end

        private

        attr_reader :root_namespace_id

        # The system-defined fallback preserves the pre-existing behavior for types
        # that were always status-capable (issue, task): it returns their
        # system-defined lifecycle unconditionally, even in namespaces where the
        # status license is unavailable (the widget is hidden there but the
        # lifecycle still resolves, as it did before this change).
        #
        # For a type whose status support is gated by a feature flag (epic) we must
        # return nil while the flag is off so the type is fully dormant. We gate on
        # the flag rather than raw widget presence so that only flag-off suppresses
        # resolution - a missing license does not (matching non-epic behavior).
        def system_defined_lifecycle_for(type)
          return if status_feature_flag_disabled_for?(type)

          type.system_defined_lifecycle
        end

        # Only flag-gated types (epic) pay for the namespace lookup; issue/task
        # resolve as before, including with a nil namespace.
        def status_feature_flag_disabled_for?(type)
          return false unless status_flag_gated_type?(type)

          !::WorkItems::Statuses::FeatureFlags.status_enabled_for_base_type?(type.base_type, root_namespace)
        end

        def index
          ::Gitlab::SafeRequestStore.fetch(cache_key) { build_index }
        end
        strong_memoize_attr :index

        def bust_index_cache
          ::Gitlab::SafeRequestStore.delete(cache_key)
          clear_memoization(:index)
          clear_memoization(:masked_lifecycle)
          clear_memoization(:masked_types)
        end

        def cache_key
          "work_items_lifecycle_provider:#{root_namespace_id}"
        end

        def build_index
          type_custom_lifecycles.each_with_object({}) do |type_custom_lifecycle, memo|
            memo[type_custom_lifecycle.work_item_type_id] = type_custom_lifecycle.lifecycle
          end
        end

        def type_custom_lifecycles
          ::WorkItems::TypeCustomLifecycle
            .with_namespace_id(root_namespace_id)
            .includes(lifecycle: [
              :statuses, :default_open_status, :default_closed_status, :default_duplicate_status
            ])
        end

        # Only flag-gated types (epic) are masked; issue/task must keep their
        # pre-mask resolution untouched while this rolls out.
        def status_flag_gated_type?(type)
          ::WorkItems::Statuses::FeatureFlags.status_flag_gated_base_types.include?(type.base_type.to_s)
        end

        # Masked resolution: a flag-gated status-capable type with no direct row
        # resolves to the Issue type's lifecycle (so it never diverges from Issue),
        # or the first available custom lifecycle when Issue itself has no row.
        def masked_lifecycle
          index[default_issue_type&.persistable_id] || index.each_value.first
        end
        strong_memoize_attr :masked_lifecycle

        # Same gate as ensure_connection! so every type listed here can have
        # its connection persisted.
        def masked_types
          gated_base_types = ::WorkItems::Statuses::FeatureFlags.status_flag_gated_base_types

          types_provider.by_base_types(gated_base_types).select do |type|
            !index.key?(type.persistable_id) && type_supports_status?(type)
          end
        end
        strong_memoize_attr :masked_types

        # Only consulted for flag-gated types. Widget presence composes the status
        # license and the per-type feature flag, so a gated type stays dormant when
        # either is missing. The check needs a namespace object (widgets are
        # resolved against the resource_parent), resolved from the id below.
        def type_supports_status?(type)
          return false unless root_namespace

          type.widgets(root_namespace).any? { |widget_def| widget_def.widget_type == 'status' }
        end

        def default_issue_type
          types_provider.default_issue_type
        end
        strong_memoize_attr :default_issue_type

        def types_provider
          ::WorkItems::TypesFramework::Provider.new(root_namespace)
        end
        strong_memoize_attr :types_provider

        # Resolved once per namespace per request and shared across provider
        # instances via the request store, mirroring the index cache.
        def root_namespace
          return unless root_namespace_id

          ::Gitlab::SafeRequestStore.fetch(namespace_cache_key) do
            ::Namespace.find_by_id(root_namespace_id)
          end
        end
        strong_memoize_attr :root_namespace

        def namespace_cache_key
          "work_items_lifecycle_provider_namespace:#{root_namespace_id}"
        end
      end
    end
  end
end
