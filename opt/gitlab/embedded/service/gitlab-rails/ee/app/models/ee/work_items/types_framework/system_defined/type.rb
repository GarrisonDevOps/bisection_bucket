# frozen_string_literal: true

module EE
  module WorkItems
    module TypesFramework
      module SystemDefined
        module Type
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          prepended do
            include ::WorkItems::OrganizationLicenseCheck
            include ::WorkItems::Statuses::Lifecycles::HasLifecycle
          end

          BASE_TYPES = [
            ::WorkItems::TypesFramework::SystemDefined::Definitions::Epic.configuration,
            ::WorkItems::TypesFramework::SystemDefined::Definitions::KeyResult.configuration,
            ::WorkItems::TypesFramework::SystemDefined::Definitions::Objective.configuration,
            ::WorkItems::TypesFramework::SystemDefined::Definitions::Requirement.configuration,
            ::WorkItems::TypesFramework::SystemDefined::Definitions::TestCase.configuration
          ].freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :fixed_items
            def fixed_items
              super + BASE_TYPES
            end
          end

          # Long-term these per-type predicates should be replaced with a single is_base_type?(name)
          # method to avoid meta-programming and method_missing issues between CE/EE type classes.
          # See https://gitlab.com/gitlab-org/gitlab/-/work_items/592881
          BASE_TYPES.each do |type|
            define_method :"#{type[:base_type]}?" do
              base_type == type[:base_type]
            end
          end

          # Augment system-defined descendants with sibling non-converted custom types from
          # the namespace. Without this override, a system-defined parent (e.g. Epic) would
          # only see other system-defined types in its descendants list, dropping custom
          # types persisted under their own AR primary key. The augmentation is delegated
          # to `Custom::Type` to keep the custom-type semantics in one place.
          override :descendant_types
          def descendant_types(resource_parent: nil)
            ::WorkItems::TypesFramework::Custom::Type.augment_with_sibling_custom_descendants(
              super,
              resource_parent
            )
          end

          override :widgets
          def widgets(resource_parent)
            # Only include widgets if the resource_parent has the appropriate license or if the widget is not licensed
            super
              .reject { |widget_def| !widget_def.licensed?(resource_parent) }
              .reject { |widget_def| feature_flag_disabled?(widget_def, resource_parent) }
          end

          # Returns types this type can be converted to, resolved via the Provider so converted
          # custom types replace their system-defined counterparts.
          #
          # EE extends the CE list by: (1) re-including the source's own base_type so sibling
          # custom types (e.g. two based on :issue) can convert to each other; (2) including
          # non-converted custom types matching any allowed base_type; (3) excluding the source
          # by identity (not base_type) to preserve sibling custom-to-custom conversions.
          #
          # When called on a Custom::Type, delegation routes here; `source` lets callers pass
          # the original custom type so identity-based exclusion targets the right type.
          override :supported_conversion_types
          def supported_conversion_types(resource_parent, user, source: self)
            allowed_base_types = supported_conversion_base_types(resource_parent, user).map(&:to_s).to_set
            # Re-add source's base_type so sibling custom types are reachable.
            allowed_base_types << source.base_type.to_s

            types_provider(resource_parent).all_ordered_by_name.select do |candidate|
              next false if allowed_base_types.exclude?(candidate.base_type.to_s)
              next false if same_type?(source, candidate)
              next false if replaces_source_system_type?(source, candidate)
              next false if candidate.archived? || !candidate.enabled

              true
            end
          end

          def system_defined_lifecycle
            ::WorkItems::Statuses::SystemDefined::Lifecycle.of_work_item_base_type(base_type)
          end

          private

          def feature_flag_disabled?(widget_def, resource_parent)
            actor = resource_parent.try(:root_ancestor)

            case widget_def.widget_type
            when 'agent_plan' then ::Feature.disabled?(:workplan, actor)
            when 'decision_log' then ::Feature.disabled?(:decision_log, actor)
            when 'custom_fields' then ticket? && ::Feature.disabled?(:work_item_ticket_migration, actor)
            # Status is root-ancestor scoped; non-flag-gated types (issue, task) are always enabled.
            when 'status' then !::WorkItems::Statuses::FeatureFlags.status_enabled_for_base_type?(base_type, actor)
            else false
            end
          end

          # Excludes the source from its own conversion list. Compares by identity (class + id)
          # rather than base_type so sibling custom types (e.g. "Bug" and "Access request", both
          # based on :issue) can convert to each other. Distinct custom types converted from the
          # same system type have different identities.
          def same_type?(source, candidate)
            candidate_identity(source) == candidate_identity(candidate)
          end

          # When the source is a system-defined type that's been converted to a custom type in
          # the namespace, the Provider returns the custom type in its place. Exclude it since
          # converting from the system type to its replacement is effectively the same identity.
          def replaces_source_system_type?(source, candidate)
            return false if source.is_a?(::WorkItems::TypesFramework::Custom::Type)
            return false unless candidate.is_a?(::WorkItems::TypesFramework::Custom::Type)
            return false if candidate.converted_from_system_defined_type_identifier.blank?

            candidate.converted_from_system_defined_type_identifier == source.id
          end

          def candidate_identity(type)
            if type.is_a?(::WorkItems::TypesFramework::Custom::Type)
              [:custom, type.id]
            else
              [:system, type.id]
            end
          end

          override :supported_conversion_base_types
          def supported_conversion_base_types(resource_parent, user)
            return [] unless supports_conversion?

            ce_types = super - ee_base_type_names
            ee_types = licensed_conversion_types(resource_parent)
            ee_types = filter_conversion_types(ee_types, resource_parent, user)

            ce_types + ee_types
          end

          override :authorized_types
          def authorized_types(types, resource_parent, licenses_for_relation)
            return super unless licenses_for_relation

            types.select do |type|
              license_name = licenses_for_relation[type.base_type]
              next type unless license_name

              resource_parent&.licensed_feature_available?(license_name)
            end
          end

          def supports_conversion?
            value = configuration_class.try(:supports_conversion?)
            value.nil? || value
          end

          def epic_allowed?(resource_parent, user)
            group = extract_group_from_resource(resource_parent)
            group && Ability.allowed?(user, :create_epic, group)
          end

          def ee_base_type_names
            BASE_TYPES.pluck(:base_type) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- It's an array of hashed not active record relations
          end

          def licensed_conversion_types(resource_parent)
            self.class.all.filter_map do |type|
              next unless type.licensed? && type.can_be_conversion_target?
              next unless feature_available_for_resource?(resource_parent, type.license_name.to_sym)

              type.base_type.to_s
            end
          end

          def filter_conversion_types(types, resource_parent, user)
            types -= %w[epic] unless epic_convertible?(resource_parent, user)
            types -= %w[objective key_result] unless okrs_enabled?(resource_parent)
            types
          end

          def epic_convertible?(resource_parent, user)
            issue? && epic_allowed?(resource_parent, user)
          end

          def okrs_enabled?(resource_parent)
            project = extract_project_from_resource(resource_parent)
            project && ::Feature.enabled?(:okrs_mvc, project)
          end

          def extract_group_from_resource(resource_parent)
            case resource_parent
            when ::Organizations::Organization
              nil
            when Group
              resource_parent
            else
              resource_parent&.group
            end
          end

          def extract_project_from_resource(resource_parent)
            if resource_parent.is_a?(Project)
              resource_parent
            elsif resource_parent.respond_to?(:project)
              resource_parent.project.presence
            end
          end
        end
      end
    end
  end
end
