# frozen_string_literal: true

module WorkItems
  module TypesFramework
    module Custom
      class Type < ApplicationRecord
        self.table_name = 'work_item_custom_types'

        include ActiveRecord::FixedItemsModel::HasOne
        include ::WorkItems::Statuses::Lifecycles::HasLifecycle

        MAX_TYPE_PER_PARENT = 40

        # Offset used when computing synthetic widget definition IDs for custom types.
        # Must be larger than any seeded system-defined widget definition ID to avoid
        # collisions, since FixedItemsModel treats equal (class, id) as the same object
        # (see #widget_definitions).
        WIDGET_DEFINITION_ID_OFFSET = 10_000

        # These names are reserved to prevent conflicts with existing GitLab features
        # and potential future work item types. Users cannot create custom work item
        # types with these names. See https://gitlab.com/gitlab-org/gitlab/-/issues/583832
        RESERVED_NAMES = %w[
          vulnerability
          merge_request
          commit
          pipeline
          alert
          review
          diff
          report
          sha
        ].freeze

        belongs_to :organization, class_name: 'Organizations::Organization', optional: true
        belongs_to :namespace, optional: true
        belongs_to_fixed_items :converted_from_system_defined_type,
          fixed_items_class: WorkItems::TypesFramework::SystemDefined::Type,
          foreign_key: 'converted_from_system_defined_type_identifier'

        enum :icon_name, ::WorkItems::TypesFramework::IconDefinitions::ENUM_MAPPING, validate: {
          message: ->(_object, _data) {
            format(_("is not valid. Valid icon names are: %{valid_names}"),
              valid_names: icon_names.keys.sort.join(', '))
          }
        }

        before_validation :strip_whitespaces

        validates :name, presence: true
        validates :name, length: { maximum: 48 }
        validates :icon_name, presence: true
        validates :name, uniqueness: { case_sensitive: false, scope: [:organization_id, :namespace_id] }

        validates_with ExactlyOnePresentValidator, fields: :sharding_keys

        validate :system_defined_names_unique_across_parent_scope
        validate :reserved_name_not_used
        validate :max_types_per_parent_limit, on: :create
        validate :unarchiving_within_limit, on: :update

        scope :for_organization, ->(organization) { where(organization_id: organization.id) }
        scope :for_namespace, ->(namespace) { where(namespace_id: namespace.id) }
        scope :order_by_name_asc, -> { order(arel_table[:name].lower.asc) }
        scope :active, -> { where(archived: false) }

        # Augments a list of system-defined descendant types with sibling non-converted
        # custom types from the same namespace whose `delegation_source.id` matches one
        # of the system descendants. Called from the EE override of
        # `SystemDefined::Type#descendant_types` so the expanded descendant list is produced
        # by a single source of truth and is reached transparently when a `Custom::Type`
        # delegates `descendant_types` to its `delegation_source` (a `SystemDefined::Type`).
        def self.augment_with_sibling_custom_descendants(system_descendants, resource_parent)
          return system_descendants unless resource_parent

          allowed_source_ids = system_descendants.map(&:persistable_id).to_set
          custom_descendants = ::WorkItems::TypesFramework::Provider.new(resource_parent).all.select do |type|
            next false unless type.is_a?(::WorkItems::TypesFramework::Custom::Type)
            next false unless type.non_converted_custom_type?

            allowed_source_ids.include?(type.delegation_source.id)
          end

          system_descendants + custom_descendants
        end

        # Until we have widget customization etc. we can simply delegate to the system defined type
        delegate :base_type, :widget_classes,
          :allowed_child_types, :allowed_parent_types, :descendant_types,
          :supports_roadmap_view?, :use_legacy_view?, :can_promote_to_objective?,
          :supports_move_action?, :service_desk?, :incident_management?, :configurable?, :creatable?,
          :visible_in_settings?, :only_for_group?, :enabled?, :system_defined_lifecycle,
          :filterable_list_view?, :filterable_board_view?,
          :disabled_workflow_type?, :okr?, :supports_assignee?, :supports_time_tracking?, :license_name,
          :can_be_conversion_target?, to: :delegation_source

        # Not a simple delegation: the system-defined expansion must exclude *this* custom type
        # by identity (not the underlying system type), so pass self as the source to keep
        # sibling custom-to-custom conversions reachable.
        def supported_conversion_types(resource_parent, user)
          delegation_source.supported_conversion_types(resource_parent, user, source: self)
        end

        # Long-term these per-type predicates should be replaced with a single is_base_type?(name)
        # method to avoid meta-programming and method_missing issues between CE/EE type classes.
        # See https://gitlab.com/gitlab-org/gitlab/-/work_items/592881
        WorkItems::TypesFramework::SystemDefined::Type.fixed_items.each do |type|
          delegate :"#{type[:base_type]}?", to: :delegation_source
        end

        def to_global_id(_options = {})
          converted_from_system_defined_type&.to_global_id ||
            ::Gitlab::GlobalId.build(self, model_name: 'WorkItems::Type', id: id)
        end
        alias_method :to_gid, :to_global_id

        def parent
          organization || namespace
        end

        def non_converted_custom_type?
          converted_from_system_defined_type_identifier.nil?
        end

        def persistable_id
          converted_from_system_defined_type_identifier || id
        end

        def widget_definitions
          type_id = persistable_id
          delegation_source.widget_definitions.map do |definition|
            # FixedItemsModel uses id for equality (== and hash), so we need unique ids
            # per custom type to prevent caching/sharing issues. We use the Cantor pairing
            # function which guarantees unique output for any pair of non-negative integers.
            # We then offset by WIDGET_DEFINITION_ID_OFFSET so that the result cannot
            # collide with existing system-defined widget definition IDs (which are small
            # positive integers). Without the offset, small pairs like (6, 1) produce 29,
            # which collides with a seeded WidgetDefinition and breaks GraphQL field
            # resolution because FixedItemsModel treats equal (class, id) as the same object.
            # See: https://en.wikipedia.org/wiki/Pairing_function#Cantor_pairing_function
            unique_id = WIDGET_DEFINITION_ID_OFFSET +
              (((definition.id + type_id) * (definition.id + type_id + 1) / 2) + type_id)
            attrs = definition.attributes.symbolize_keys.merge(
              id: unique_id,
              work_item_type_id: type_id
            )
            definition.class.new(attrs)
          end
        end

        def widgets(resource_parent)
          widget_definitions
            .filter(&:widget_class)
            .select { |widget_def| widget_def.licensed?(resource_parent) }
            .reject { |widget_def| feature_flag_disabled?(widget_def, resource_parent) }
        end

        def delegation_source
          # use the associated system defined type as delegation source if set otherwise default to issue base type
          converted_from_system_defined_type || ::WorkItems::TypesFramework::Provider.new.default_issue_type
        end

        # See WorkItems::TypesFramework::SystemDefined::Type#system_defined_type_id.
        # Custom types delegate hierarchy semantics (and other cross-cutting
        # system-defined lookups) to delegation_source so that, for example,
        # a non-converted custom type inherits the allowed-children of Issue.
        def system_defined_type_id
          delegation_source.id
        end

        private

        def feature_flag_disabled?(widget_def, resource_parent)
          actor = resource_parent.try(:root_ancestor)

          case widget_def.widget_type
          when 'agent_plan' then ::Feature.disabled?(:workplan, actor)
          when 'decision_log' then ::Feature.disabled?(:decision_log, actor)
          # base_type comes from the delegation source, so a custom type based on epic shares its flag.
          when 'status' then !::WorkItems::Statuses::FeatureFlags.status_enabled_for_base_type?(base_type, actor)
          else false
          end
        end

        def strip_whitespaces
          self.name = name&.strip
        end

        def sharding_keys
          [:namespace_id, :organization_id]
        end

        def normalize_name(value)
          value.downcase.gsub(/[\s-]+/, '_')
        end

        def reserved_name_not_used
          return if name.blank?

          normalized = normalize_name(name)
          return unless RESERVED_NAMES.include?(normalized)

          display_name = normalized.tr('_', ' ').titleize
          errors.add(:name, format(_("'%{name}' is a reserved name and cannot be used."), name: display_name))
        end

        def system_defined_names_unique_across_parent_scope
          return if name.blank?

          normalized_input = normalize_name(name)
          system_type = WorkItems::TypesFramework::SystemDefined::Type.all.find do |t|
            normalize_name(t.name) == normalized_input
          end

          return unless system_type

          # Allow the same name if this custom type is converted from that exact system defined type
          return if converted_from_system_defined_type_identifier == system_type.id

          # Allow if the system-defined name is available across namespace/organization
          # i.e a type was converted from the :issue type but renamed to something else, so "Issue" is still available
          return if system_defined_name_available?(system_type)

          errors.add(:name, format(_("'%{name}' is already taken."), name: system_type.name))
        end

        def system_defined_name_available?(system_type)
          converted_type = self.class
            .where(parent_scope_conditions)
            .excluding(self)
            .find_by(converted_from_system_defined_type_identifier: system_type.id)

          # Name is available if there's a converted type that uses a DIFFERENT name
          # than the system defined type it was converted from
          converted_type.present? && !(converted_type.name.casecmp(system_type.name) == 0)
        end

        def max_types_per_parent_limit
          return unless organization_id.present? || namespace_id.present?
          return unless total_types_count + additional_active_type_count > MAX_TYPE_PER_PARENT

          parent_attribute = organization_id.present? ? :organization : :namespace

          errors.add(parent_attribute,
            format(_('can only have a maximum of %{limit} work item types.'), limit: MAX_TYPE_PER_PARENT)
          )
        end

        def total_types_count
          active_custom_types_count + system_defined_types_count
        end

        def additional_active_type_count
          non_converted_custom_type? && !archived? ? 1 : 0
        end

        def active_custom_types_count
          self.class
            .where(parent_scope_conditions)
            .where(converted_from_system_defined_type_identifier: nil)
            .active
            .count
        end

        def system_defined_types_count
          provider = WorkItems::TypesFramework::Provider.new(parent)
          provider.available_system_defined_types_count - archived_converted_types_count
        end

        def archived_converted_types_count
          self.class
            .where(parent_scope_conditions)
            .where.not(converted_from_system_defined_type_identifier: nil)
            .where(archived: true)
            .count
        end

        def unarchiving_within_limit
          return unless archived_changed?(from: true, to: false)
          return unless total_types_count >= MAX_TYPE_PER_PARENT

          errors.add(:base,
            format(_('Cannot unarchive because the maximum limit of %{limit} work item types has been reached.'),
              limit: MAX_TYPE_PER_PARENT)
          )
        end

        def parent_scope_conditions
          if organization_id.present?
            { organization_id: organization_id }
          else
            { namespace_id: namespace_id }
          end
        end
      end
    end
  end
end
