# frozen_string_literal: true

module EE
  module WorkItems
    module TypesFramework
      module Provider
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        def invalidate_cache!
          ::Gitlab::SafeRequestStore.delete(cache_key)
          ::Gitlab::SafeRequestStore.delete(custom_types_cache_key)
          clear_memoization(:indexed_cache)
          clear_memoization(:visibility_map)
        end

        override :by_base_types
        def by_base_types(names)
          return super unless feature_available?

          base_type_names = Array(names).map(&:to_s).to_set
          indexed_cache.values.uniq.select { |type| base_type_names.include?(type.base_type.to_s) }
        end

        override :allowed_types
        def allowed_types
          types = super

          types.reject!(&:disabled_workflow_type?)
          types |= [find_by_base_type(:epic)] if epics_enabled?
          types |= [find_by_base_type(:objective), find_by_base_type(:key_result)] if okrs_enabled?
          types
        end

        # TODO: Integrate filtering into .all
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/585707
        override :filtered_types
        def filtered_types
          all
            .reject { |type| disabled_workflow_type_unavailable?(type) }
            .reject { |type| epic_unavailable?(type) }
            .reject { |type| okr_unavailable?(type) }
        end

        # Like #filtered_types, but:
        # - OKR availability skips the `project_namespace?` guard so groups
        #   and their projects answer identically.
        # - On project namespaces with epics licensed, the epic type is
        #   always included and its `enabled` flag reflects
        #   `project_epics_enabled?` instead of being rejected when the FF
        #   is off. When epics are not licensed the type is excluded
        #   regardless of namespace.
        override :available_types
        def available_types
          types = all
            .reject { |type| disabled_workflow_type_unavailable?(type) }
            .reject { |type| epic_unavailable?(type, skip_project_namespace_check: true) }
            .reject { |type| okr_unavailable?(type, skip_project_namespace_check: true) }

          return types unless project_namespace?

          types.map { |type| type.base_type.to_s == 'epic' ? project_epic_type(type) : type }
        end

        private

        override :resolve_by_id
        def resolve_by_id(id)
          return super unless feature_available?

          indexed_cache[id] || super
        end

        override :resolve_by_base_type
        def resolve_by_base_type(name)
          return super unless feature_available?

          system_type = ::WorkItems::TypesFramework::SystemDefined::Type.default_by_type(name)
          return unless system_type

          indexed_cache[system_type.id] || super
        end

        override :resolve_all
        def resolve_all
          return super unless feature_available?

          indexed_cache.values.uniq
        end

        # Memoized per Provider instance to avoid repeated SafeRequestStore hash lookups
        # when multiple resolve_* methods are called on the same provider.
        # The SafeRequestStore layer shares the built cache across Provider instances
        # within the same request, so the expensive build_indexed_lookup only runs once
        # per namespace per request.
        def indexed_cache
          ::Gitlab::SafeRequestStore.fetch(cache_key) { build_indexed_lookup }
        end
        strong_memoize_attr :indexed_cache

        def cache_key
          "work_items_types_provider:#{namespace.class.base_class.name}:#{namespace.id}"
        end

        def build_indexed_lookup
          custom = custom_types

          converted_system_type_ids = custom.filter_map(&:converted_from_system_defined_type_identifier).to_set
          system_defined = system_defined_types.reject { |type| converted_system_type_ids.include?(type.id) }

          sorted = (custom + system_defined).sort_by { |type| type.name.downcase }

          sorted.each_with_object({}) do |type, hash|
            cache_id = type.persistable_id
            enabled = visibility_map.fetch(cache_id, true)
            cached = ::WorkItems::TypesFramework::NamespacedType.new(type, enabled: enabled,
              is_a_group: group_namespace?, tasks_on_boards: tasks_on_boards?, namespace: namespace)

            hash[cache_id] = cached
            # Converted custom types are primarily indexed under the system-defined type ID
            # they replaced (so find_by_base_type and existing DB references resolve correctly).
            # We also index under the custom type's own AR ID so that round-trips through
            # fetch_work_item_type work: code that resolves a type from the cache, reads .id
            # from it (the AR PK), and passes it back through find_by_id will find the same
            # object. Without this, HasType#work_item_type= breaks for converted types because
            # it extracts .id (the custom AR PK) and looks it up again.
            # Both keys point to the same NamespacedType instance - no memory duplication.
            hash[type.id] = cached if cache_id != type.id
          end
        end

        def system_defined_types
          ::WorkItems::TypesFramework::SystemDefined::Type.all
        end

        # Custom types depend only on the organization or root namespace, so share them
        # across the Provider instances of every namespace under it within a request.
        def custom_types
          ::Gitlab::SafeRequestStore.fetch(custom_types_cache_key) do
            if organization_namespace?
              ::WorkItems::TypesFramework::Custom::Type.for_organization(root_ancestor).to_a
            elsif namespace_scoped_custom_types?
              ::WorkItems::TypesFramework::Custom::Type.for_namespace(root_ancestor).to_a
            else
              ::WorkItems::TypesFramework::Custom::Type.where(organization_id: namespace.organization_id).to_a
            end
          end
        end

        def custom_types_cache_key
          if organization_namespace?
            "work_items_types_provider:custom_types:org:#{root_ancestor.id}"
          elsif namespace_scoped_custom_types?
            "work_items_types_provider:custom_types:root_ns:#{root_ancestor.id}"
          else
            "work_items_types_provider:custom_types:org:#{namespace.organization_id}"
          end
        end

        def namespace_scoped_custom_types?
          ::Gitlab::Saas.feature_available?(:namespace_scoped_work_item_types)
        end

        # Returns a { work_item_type_id => enabled } map for the current namespace.
        # Short-circuits to {} (all types default to enabled) when:
        # - namespace is an Organization (visibility is namespace-scoped only)
        # - no settings record exists, or customizable_type_visibility is false
        def visibility_map
          return {} if organization_namespace?

          # Cache settings by org/root-namespace key so multiple Provider instances
          # for different namespaces within the same org share one DB lookup per request.
          settings = ::Gitlab::SafeRequestStore.fetch(work_item_settings_cache_key) do
            ::WorkItems::Settings.for_namespace(namespace)
          end
          return {} unless settings&.customizable_type_visibility

          ::WorkItems::TypesFramework::Visibility.resolve_for_namespace(namespace)
        end
        strong_memoize_attr :visibility_map

        def work_item_settings_cache_key
          if ::Gitlab::Saas.feature_available?(:namespace_scoped_work_item_types)
            "work_item_settings_root_ns_#{root_ancestor&.id}"
          else
            "work_item_settings_org_#{namespace.try(:organization_id)}"
          end
        end

        # Memoized per Provider instance because this is called on every resolve_* entry
        # point. Each work item holds its own Provider (via HasType), so without memoization
        # the feature flag + traversal_ids check would run on every work_item_type access.
        def feature_available?
          return false if namespace.nil?

          return true if organization_namespace?

          # Read the root ancestor ID directly from the traversal_ids column, which is
          # already loaded on the namespace record. This avoids the DB query that
          # namespace.root_ancestor would trigger (Namespace.find_by(id: traversal_ids.first)).
          # Falls back to root_ancestor for non-Namespace objects (e.g. Project) that
          # lack traversal_ids.
          root_id = namespace.try(:traversal_ids)&.first
          root_id ||= root_ancestor.id

          return false unless root_id
          return false if root_id == namespace.id && namespace.try(:user_namespace?)
          return false if root_ancestor.user_namespace?

          true
        end
        strong_memoize_attr :feature_available?

        def organization_namespace?
          namespace.is_a?(::Organizations::Organization)
        end

        def disabled_workflow_type_unavailable?(type)
          return false unless type.disabled_workflow_type?

          !licensed_feature_enabled?(type.license_name)
        end

        def epic_unavailable?(type, skip_project_namespace_check: false)
          return false unless type.base_type.to_s == 'epic'

          !epics_enabled?(skip_project_namespace_check: skip_project_namespace_check)
        end

        # Wraps the epic type for a project namespace so `enabled` reflects
        # the `project_epics_enabled?` FF state on the resource_parent. Used
        # by #available_types to include the epic type even when the FF is
        # off, so the UI can show it as disabled rather than missing.
        #
        # `is_a_group` is set to true when the namespace is a real group, or
        # when it is a project with `project_epics_enabled?` true. This
        # makes `visible_in_context?` treat the epic as visible (the
        # underlying type is `only_for_group? = true`, which would otherwise
        # force `enabled?` to false on projects). Organization and user
        # namespaces correctly resolve to false.
        def project_epic_type(type)
          ::WorkItems::TypesFramework::NamespacedType.new(
            type.__getobj__,
            enabled: epics_enabled?,
            is_a_group: group_namespace? || (project_namespace? && resource_parent.try(:project_epics_enabled?)),
            tasks_on_boards: tasks_on_boards?
          )
        end

        def okr_unavailable?(type, skip_project_namespace_check: false)
          return false unless type.okr?

          !okrs_enabled?(skip_project_namespace_check: skip_project_namespace_check)
        end

        def licensed_feature_enabled?(feature)
          strong_memoize_with(:licensed_feature_enabled, feature) do
            next false if resource_parent.nil?

            next License.feature_available?(feature) if organization_namespace?

            resource_parent.licensed_feature_available?(feature)
          end
        end

        # When `skip_project_namespace_check` is true, project namespaces
        # answer based on license alone (bypassing `project_epics_enabled?`),
        # so the epic type is surfaced whenever licensed and the FF state is
        # reflected via #project_epic_type.
        def epics_enabled?(skip_project_namespace_check: false)
          strong_memoize_with(:epics_enabled, skip_project_namespace_check) do
            if resource_parent.nil?
              false
            elsif organization_namespace?
              License.feature_available?(:epics)
            elsif project_namespace? && !skip_project_namespace_check
              resource_parent.try(:project_epics_enabled?)
            else
              resource_parent.licensed_feature_available?(:epics)
            end
          end
        end

        # When `skip_project_namespace_check` is true, the `project_namespace?`
        # guard is bypassed so that groups (and any other non-project
        # namespaces) can also answer "OKRs enabled" based purely on the FF
        # state of the resource_parent. Used by #available_types to keep
        # group/project answers in sync.
        def okrs_enabled?(skip_project_namespace_check: false)
          strong_memoize_with(:okrs_enabled, skip_project_namespace_check) do
            if resource_parent.nil?
              false
            elsif organization_namespace?
              ::Feature.enabled?(:okrs_mvc, :instance)
            elsif skip_project_namespace_check
              resource_parent.okrs_mvc_feature_flag_enabled?
            else
              project_namespace? && resource_parent.okrs_mvc_feature_flag_enabled?
            end
          end
        end
      end
    end
  end
end
