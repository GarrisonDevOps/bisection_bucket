# frozen_string_literal: true

module WorkItems
  module Lifecycles
    class BaseService < ::BaseContainerService
      include Gitlab::InternalEventsTracking

      def initialize(...)
        super

        init_and_reset_status_data!
      end

      private

      def init_and_reset_status_data!
        @statuses_to_create = []
        @statuses_to_update = []
        @statuses_to_remove = []
      end

      def ensure_custom_lifecycle_and_status!
        return if group.custom_lifecycles.exists?

        ::WorkItems::Statuses::SystemDefined::Lifecycle.all.each do |system_defined_lifecycle| # rubocop:disable Rails/FindEach -- hard-coded data
          apply_status_changes(system_defined_lifecycle.statuses.map { |s| { id: s.to_gid } })

          statuses = @processed_statuses
          default_statuses = default_statuses_for_lifecycle(
            statuses,
            {}, # Don't pass any params, use fallback only
            fallback_lifecycle: system_defined_lifecycle,
            force_resolve: true
          )

          ::WorkItems::Statuses::Custom::Lifecycle.create!(
            namespace: group,
            name: system_defined_lifecycle.name,
            work_item_types: system_defined_lifecycle.work_item_types(group),
            statuses: statuses,
            default_open_status: default_statuses[:default_open_status],
            default_closed_status: default_statuses[:default_closed_status],
            default_duplicate_status: default_statuses[:default_duplicate_status],
            created_by: current_user
          ).tap do
            remove_system_defined_board_lists
          end

          track_internal_events_for_statuses
          init_and_reset_status_data!
        end

        @converted_system_defined_lifecycle = true
      end

      def converted_system_defined_lifecycle?
        @converted_system_defined_lifecycle == true
      end

      # Rows written before the conversion still hold system-defined status ids.
      def schedule_converted_status_backfill
        ::WorkItems::Statuses::BackfillConvertedStatusIdsWorker.perform_async(group.id)
      end

      def apply_status_changes(statuses_to_process)
        # We need to ensure the new custom lifecycle has the correct set of statuses
        # if they weren't defined explicitly.
        if statuses_to_process.blank? && system_defined_lifecycle?
          statuses_to_process = lifecycle.statuses.map { |s| { id: s.to_gid } }
        end

        @processed_statuses = process_statuses(statuses_to_process)
        return unless statuses_to_process.present?

        # Only calculate items to remove when lifecycle already persisted
        @statuses_to_remove = calculate_statuses_to_remove if lifecycle.present?
      end

      def process_statuses(statuses)
        return [] unless statuses.present?

        statuses.map { |status_params| process_single_status(status_params) }
      end

      def process_single_status(status_params)
        if status_params[:id].present?
          handle_status_with_id(status_params)
        else
          handle_status_without_id(status_params)
        end
      end

      def handle_status_with_id(status_params)
        status = find_by_gid(status_params[:id])

        case status
        when ::WorkItems::Statuses::SystemDefined::Status
          convert_system_to_custom_status!(status, status_params)
        when ::WorkItems::Statuses::Custom::Status
          ensure_status_belongs_to_namespace!(status)
          update_custom_status!(status, status_params)
          status
        end
      end

      def handle_status_without_id(status_params)
        existing_status = find_custom_status_by_name(status_params[:name])

        if existing_status
          update_custom_status!(existing_status, status_params)
          existing_status
        else
          create_custom_status!(prepare_custom_status_params(status_params)).tap do |status|
            @statuses_to_create << status
          end
        end
      end

      def convert_system_to_custom_status!(system_defined_status, status_params)
        prepared_params = prepare_custom_status_params(status_params, system_defined_status, system_defined_status.id)
        create_custom_status!(prepared_params).tap do |status|
          @statuses_to_update << status if converted_with_changes?(system_defined_status, status)
        end
      end

      def converted_with_changes?(system_defined_status, status)
        system_defined_status.name != status.name ||
          system_defined_status.color != status.color ||
          status.description.present?
      end

      def create_custom_status!(prepared_params)
        ::WorkItems::Statuses::Custom::Status.create!(prepared_params)
      end

      def update_custom_status!(status, status_params)
        update_attributes = status_params.to_h.slice(:name, :description, :color, :category)
        update_attributes.delete(:category) if update_attributes[:category].blank?

        ensure_category_change_is_safe!(status, update_attributes)

        expire_mappings_from_status(status) if lifecycle.present?

        status.assign_attributes(update_attributes)

        return unless status.changed?

        @statuses_to_update << status

        status.updated_by = current_user
        status.save!
      end

      def ensure_category_change_is_safe!(status, update_attributes)
        return unless update_attributes.key?(:category)

        new_category = update_attributes[:category].to_s
        return if status.category == new_category

        if used_in_other_lifecycle?(status)
          raise StandardError, format(
            s_('WorkItem|"%{status_name}" is already in the "%{category}" category. A status keeps ' \
              'its category in every lifecycle that uses it. To use a different category, create a ' \
              'status with a different name.'),
            status_name: status.name,
            category: status.category.to_s.humanize
          )
        end

        return unless crosses_state_unsafely?(status, new_category)

        raise StandardError, format(
          s_('WorkItem|"%{status_name}" is already in the "%{category}" category. A status that is ' \
            'in use cannot move between open and closed states. To use a different category, create ' \
            'a status with a different name.'),
          status_name: status.name,
          category: status.category.to_s.humanize
        )
      end

      def used_in_other_lifecycle?(status)
        excluded_lifecycle_id = lifecycle.id if custom_lifecycle?
        status.used_in_lifecycle_other_than?(excluded_lifecycle_id)
      end

      def crosses_state_unsafely?(status, new_category)
        new_state = state_for_category(new_category)
        return false if new_state.nil? || status.state == new_state

        directly_in_use = lifecycle.present? && status.in_use_in_lifecycle?(lifecycle) &&
          !status.shielded_by_open_mapping?(group)

        directly_in_use || status.used_as_mapping_target?(group)
      end

      def state_for_category(category)
        matching_state, _categories = ::WorkItems::Statuses::SharedConstants::CATEGORIES_STATE.find do |_, categories|
          categories.include?(category.to_sym)
        end

        matching_state
      end

      def expire_mappings_from_status(status)
        Statuses::Custom::Mapping.originating_from_status(
          namespace: group,
          status: status,
          work_item_type: lifecycle_work_item_types
        ).where(valid_until: nil).update_all(valid_until: Time.current) # rubocop:disable CodeReuse/ActiveRecord -- query only used here
      end

      def prepare_custom_status_params(status_params, system_defined_status = nil, converted_from_id = nil)
        {
          namespace: group,
          name: status_params[:name] || system_defined_status&.name,
          color: status_params[:color] || system_defined_status&.color,
          description: status_params[:description] || system_defined_status&.description,
          category: status_params[:category] || system_defined_status&.category,
          converted_from_system_defined_status_identifier: converted_from_id,
          created_by: current_user
        }
      end

      def find_by_gid(global_id)
        global_id.model_class.find(global_id.model_id.to_i)
      end

      def find_custom_status_by_name(name)
        ::WorkItems::Statuses::Custom::Status.find_by_namespace_and_name(group.id, name)
      end

      def calculate_statuses_to_remove
        original_statuses = lifecycle.statuses.to_a

        if custom_lifecycle?
          original_statuses - @processed_statuses
        elsif system_defined_lifecycle?
          converted_ids = @processed_statuses.filter_map(&:converted_from_system_defined_status_identifier)
          original_statuses.reject { |status| converted_ids.include?(status.id) }
        end
      end

      def ensure_status_belongs_to_namespace!(status)
        return if status.namespace_id == group.id
        return if lifecycle.present? && status.namespace_id == lifecycle.namespace_id

        raise StandardError, "Status '#{status.name}' doesn't belong to this namespace."
      end

      def validate_status_removal_constraints
        return unless @statuses_to_remove&.any?

        validate_default_status_constraints
        validate_status_usage(@statuses_to_remove)
      end

      def handle_deferred_status_removal
        return unless @statuses_to_remove&.any?

        statuses_with_mappings, statuses_without_mappings = @statuses_to_remove.partition do |status|
          find_mapping_for_status(status).present?
        end

        process_statuses_with_mappings(statuses_with_mappings)
        destroy_eligible_statuses(statuses_without_mappings)
      end

      def find_mapping_for_status(status)
        status_mappings.find do |mapping|
          mapping[:old_status_id].model_id.to_i == status.id
        end
      end

      def process_statuses_with_mappings(statuses)
        statuses.each do |status_to_remove|
          mapping_input = find_mapping_for_status(status_to_remove)
          process_status_with_mapping(status_to_remove, mapping_input)
        end
      end

      def process_status_with_mapping(status_to_remove, mapping_input)
        target_status = resolve_target_status(mapping_input[:new_status_id], lifecycle_status_ids)
        source_status = maybe_convert_from_system_defined_status(status_to_remove)

        ensure_mapped_statuses_have_same_state(source_status, target_status)

        lifecycle_work_item_types.each do |work_item_type|
          # A masked type gets its real connection before its mapping so the
          # mutation never leaves a mapping without a backing lifecycle row.
          lifecycle_provider.ensure_connection!(work_item_type)

          create_or_update_mapping(source_status, target_status, work_item_type,
            old_status_role: previous_role_for_status(status_to_remove))
        end
      end

      def resolve_target_status(target_status_id, lifecycle_status_ids)
        target_status = find_by_gid(target_status_id)

        if system_defined_status?(target_status)
          # Conversion happened in a step before so we can lookup the corresponding custom status
          return WorkItems::Statuses::Custom::Status.in_namespace(group)
            .find_by_converted_status(target_status) || target_status
        end

        if lifecycle_status_ids.include?(target_status.id)
          target_status
        else
          raise StandardError,
            "Mapping target status '#{target_status.name}' does not belong to the target lifecycle"
        end
      end

      def maybe_convert_from_system_defined_status(status_to_remove)
        return status_to_remove unless system_defined_status?(status_to_remove)

        # We cannot map from a system-defined status right now
        # so we need to create a custom status although that is not in use.
        # The conversion mapping resolves the chain:
        # system-defined status --> custom status --> mapped status
        prepared_params = prepare_custom_status_params({}, status_to_remove, status_to_remove.id)
        create_custom_status!(prepared_params)
      end

      def ensure_mapped_statuses_have_same_state(source_status, target_status)
        return if source_status.state == target_status.state

        raise StandardError,
          "Mapping statuses '#{source_status.name}' and '#{target_status.name}' " \
            "must be of a category of the same state (open/closed)."
      end

      def previous_role_for_status(status)
        case status.id
        when @previous_lifecycle_default_ids[:open] then :open
        when @previous_lifecycle_default_ids[:closed] then :closed
        when @previous_lifecycle_default_ids[:duplicate] then :duplicate
        end
      end

      def destroy_eligible_statuses(statuses)
        eligible_statuses = statuses.select { |status| can_destroy_status?(status) }
        eligible_statuses.each(&:destroy!)
      end

      def can_destroy_status?(status)
        # rubocop:disable CodeReuse/ActiveRecord -- queries only used here
        status.is_a?(WorkItems::Statuses::Custom::Status) &&
          !Statuses::Custom::LifecycleStatus.exists?(namespace: group, status: status) &&
          !Statuses::Custom::Mapping.exists?(namespace: group, new_status: status)
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def create_or_update_mapping(old_status, new_status, work_item_type, valid_until: nil, old_status_role: nil)
        prevent_mapping_chains(old_status, new_status, work_item_type)

        existing_mappings = Statuses::Custom::Mapping.originating_from_status(
          namespace: group,
          status: old_status,
          work_item_type: work_item_type
        )

        repair_unbounded_mappings_from_old_status(existing_mappings, new_status)

        valid_from = calculate_valid_from_time(existing_mappings)

        # We can't use upsert here because there is no uniqueness constraint.
        # Multiple mappings with this combination can exist
        # with different valid_from/valid_until dates without overlaps
        Statuses::Custom::Mapping.where( # rubocop:disable CodeReuse/ActiveRecord -- reason above
          namespace_id: group.id,
          old_status_id: old_status.id,
          new_status_id: new_status.id,
          work_item_type_id: work_item_type.id,
          valid_from: valid_from,
          valid_until: valid_until,
          old_status_role: old_status_role
        ).first_or_create!
      end

      # Avoid creating mapping chains like A->B->C by updating existing mappings
      # that point to the status being removed to point directly to the final target
      def prevent_mapping_chains(old_status, new_status, work_item_type)
        # Prevent self references. Update all below would set A --> A if old status is A already.
        # rubocop: disable CodeReuse/ActiveRecord -- these query is only used here
        Statuses::Custom::Mapping.where(
          namespace: group,
          old_status: new_status,
          new_status: old_status,
          work_item_type_id: work_item_type.id
        ).delete_all

        Statuses::Custom::Mapping.where(
          namespace: group,
          new_status: old_status,
          work_item_type_id: work_item_type.id
        ).update_all(new_status_id: new_status.id)
        # rubocop: enable CodeReuse/ActiveRecord
      end

      # Fix invalid combinations: Another mapping might already exist from the old status.
      def repair_unbounded_mappings_from_old_status(existing_mappings, new_status)
        existing_mappings.each do |mapping|
          next if mapping.valid_until.present? || mapping.new_status_id == new_status.id

          mapping.update!(valid_until: Time.current)
        end
      end

      def calculate_valid_from_time(existing_mappings)
        return if existing_mappings.empty?

        # Latest valid_until is the desired new valid_from
        existing_mappings.filter_map(&:valid_until).max
      end

      # We need to remove associated system-defined board lists because these cannot have a
      # foreign key constraint to cascade the deletion
      def remove_system_defined_board_lists
        return unless @statuses_to_remove&.any?

        system_defined_identifiers = @statuses_to_remove.filter_map do |status|
          system_defined_status?(status) ? status.id : status.converted_from_system_defined_status_identifier
        end

        return if system_defined_identifiers.blank?

        # rubocop: disable CodeReuse/ActiveRecord -- these queries will only be used here
        Namespaces::ProjectNamespace.where('traversal_ids[1] = ?', group.id).each_batch do |project_namespaces|
          project_ids = Project.where(project_namespace_id: project_namespaces.select(:id))

          ::List.where(
            project_id: project_ids,
            system_defined_status_identifier: system_defined_identifiers
          ).delete_all
        end

        Group.where('traversal_ids[1] = ?', group.id).each_batch do |groups|
          ::List.where(
            group_id: groups,
            system_defined_status_identifier: system_defined_identifiers
          ).delete_all
        end
        # rubocop: enable CodeReuse/ActiveRecord
      end

      def validate_status_usage(statuses_to_check)
        statuses_to_check.each do |status|
          in_use = case status
                   when ::WorkItems::Statuses::SystemDefined::Status
                     status.in_use_in_namespace?(group)
                   when ::WorkItems::Statuses::Custom::Status
                     status.in_use_in_lifecycle?(lifecycle)
                   end

          next unless in_use

          unless find_mapping_for_status(status)
            raise StandardError, "Cannot remove status '#{status.name}' from lifecycle " \
              "because it is in use and no mapping is provided"
          end
        end
      end

      def validate_default_status_constraints
        status_ids = @statuses_to_remove.map(&:id)

        default_status_ids = lifecycle.default_statuses.map(&:id)
        conflicting_ids = status_ids & default_status_ids

        return unless conflicting_ids.any?

        conflicting_status = @statuses_to_remove.find { |status| conflicting_ids.include?(status.id) }

        return if find_mapping_for_status(conflicting_status)

        raise StandardError, "Cannot remove default status '#{conflicting_status.name}' without providing a mapping"
      end

      def update_lifecycle_status_positions!
        lifecycle.reset

        # Delete directly without triggering lifecycle callbacks
        WorkItems::Statuses::Custom::LifecycleStatus.where(lifecycle_id: lifecycle.id).delete_all # rubocop: disable CodeReuse/ActiveRecord -- reason above

        lifecycle_status_data = @processed_statuses.map.with_index do |status, index|
          {
            lifecycle_id: lifecycle.id,
            status_id: status.id,
            namespace_id: lifecycle.namespace_id,
            position: index
          }
        end

        ::WorkItems::Statuses::Custom::LifecycleStatus.insert_all(lifecycle_status_data) if lifecycle_status_data.any?
      end

      def default_statuses_for_lifecycle(processed_statuses, attributes, fallback_lifecycle: nil, force_resolve: false)
        default_status_mappings = {
          default_open_status: :default_open_status_index,
          default_closed_status: :default_closed_status_index,
          default_duplicate_status: :default_duplicate_status_index
        }

        default_status_mappings.each_with_object({}) do |(status_field, index_field), default_attributes|
          index = attributes[index_field]

          if index.present? && index < processed_statuses.length
            status = processed_statuses[index]
            default_attributes[status_field] = status if status
          elsif force_resolve && fallback_lifecycle.present?
            # When we create a custom lifecycle it's required to pass all default statuses
            # so we must resolve them from the system-defined lifecycle if they weren't provided.
            system_defined_default = fallback_lifecycle.try(status_field)&.id
            next if system_defined_default.blank?

            default_attributes[status_field] = processed_statuses.find do |s|
              s.converted_from_system_defined_status_identifier == system_defined_default
            end
          end
        end
      end

      def track_internal_events_for_statuses
        @statuses_to_create.each do |status|
          track_internal_event('create_custom_status_in_group_settings',
            namespace: group,
            user: current_user,
            additional_properties: {
              label: status.category.to_s
            }
          )
        end

        @statuses_to_update.each do |status|
          track_internal_event('update_custom_status_in_group_settings',
            namespace: group,
            user: current_user,
            additional_properties: {
              label: status.category.to_s
            }
          )
        end

        @statuses_to_remove.each do |status|
          track_internal_event('delete_custom_status_in_group_settings',
            namespace: group,
            user: current_user,
            additional_properties: {
              label: status.category.to_s
            }
          )
        end
      end

      def record_previous_default_statuses
        @previous_lifecycle_default_ids = {
          open: lifecycle.default_open_status_id,
          closed: lifecycle.default_closed_status_id,
          duplicate: lifecycle.default_duplicate_status_id
        }
      end

      def system_defined_status?(status)
        status.is_a?(::WorkItems::Statuses::SystemDefined::Status)
      end

      def system_defined_lifecycle?
        lifecycle.is_a?(::WorkItems::Statuses::SystemDefined::Lifecycle)
      end

      def custom_lifecycle?
        lifecycle.is_a?(::WorkItems::Statuses::Custom::Lifecycle)
      end

      def lifecycle
        return unless params[:id].present?

        find_by_gid(GlobalID.parse(params[:id]))
      end
      strong_memoize_attr :lifecycle

      # Snapshot taken before any connection is persisted, so a masked type
      # stays in the list for every status processed in this mutation.
      def lifecycle_work_item_types
        lifecycle.work_item_types(group)
      end
      strong_memoize_attr :lifecycle_work_item_types

      def lifecycle_provider
        ::WorkItems::Statuses::Lifecycles::Provider.new(group.id)
      end
      strong_memoize_attr :lifecycle_provider

      def status_mappings
        params[:status_mappings] || []
      end

      def lifecycle_status_ids
        lifecycle.statuses.map(&:id)
      end
      strong_memoize_attr :lifecycle_status_ids
    end
  end
end
