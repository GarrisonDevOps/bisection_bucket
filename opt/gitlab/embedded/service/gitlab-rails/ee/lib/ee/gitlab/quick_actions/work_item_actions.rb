# frozen_string_literal: true

module EE
  module Gitlab
    module QuickActions
      module WorkItemActions
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::QuickActions::Dsl

        included do
          desc { _('Configure checkin reminder frequency') }
          explanation do |frequency|
            format(_("Sets checkin reminder frequency to %{frequency}."), frequency: frequency)
          end
          params "<#{::WorkItems::Progress.reminder_frequencies.keys.join(' | ')}"
          types WorkItem
          condition do
            ::Feature.enabled?(:okr_checkin_reminders,
              project) && quick_action_target.work_item_type.objective? && Ability.allowed?(current_user, :admin_issue,
                project)
          end
          parse_params do |frequency|
            find_frequency(frequency)
          end
          command :checkin_reminder do |frequency|
            if frequency
              @execution_message[:checkin_reminder] = _('Checkin reminder has been enabled.')
              @updates[:progress] = update_progress(frequency)
            end
          end

          desc { s_("WorkItemStatus|Set status") }
          explanation do |_, status_name|
            format(s_("WorkItemStatus|Set status to %{status_name}."), status_name: status_name)
          end
          types WorkItem
          params '"Name of the status"'
          condition do
            quick_action_target.resource_parent&.root_ancestor&.licensed_feature_available?(:work_item_status) &&
              Ability.allowed?(current_user, :"update_#{quick_action_target.to_ability_name}", quick_action_target)
          end
          parse_params do |status_name|
            namespace = quick_action_target.resource_parent&.root_ancestor
            status = ::WorkItems::Statuses::Finder.new(namespace, { 'name' => status_name.strip }).find_single_status
            [status, status_name]
          end
          command :status do |status, status_name|
            if status
              @updates[:status] = status
              @execution_message[:status] =
                format(s_("WorkItemStatus|Status set to %{status_name}."), status_name: status.name)
            else
              @execution_message[:status] =
                format(s_("WorkItemStatus|%{status_name} is not a valid status for this item."),
                  { status_name: status_name })
            end
          end
        end

        private

        override :success_msg
        def success_msg
          super.merge(promote: _('Promoted issue to an epic.'))
        end

        override :promote_to_map
        def promote_to_map
          super.merge(key_result: ['Objective'], issue: super['issue'].push('Epic'))
        end

        override :apply_type_commands
        def apply_type_commands(new_type, command)
          return super unless new_type.epic?

          begin
            ::WorkItems::LegacyEpics::IssuePromoteService
              .new(container: quick_action_target.container, current_user: current_user)
              .execute(quick_action_target)

            success_msg[command]
          rescue StandardError => e
            error_msg(:not_found, action: 'promote', error_message: e.message)
          end
        end

        override :validate_promote_to
        def validate_promote_to(type)
          return super unless type&.epic?

          container = quick_action_target.container
          issue_group = container.is_a?(Group) ? container : container.group

          return if quick_action_target.can_be_promoted_to_epic?(current_user, issue_group)

          error_msg(:not_found, action: 'promote')
        end

        override :type_change_allowed?
        def type_change_allowed?
          true unless quick_action_target.work_item_type.epic?
        end

        override :validate_type
        def validate_type(type)
          return super unless type&.epic?

          # `container` (from `WorkItems::EpicAsWorkItem#container`) already resolves to the
          # epic-owning Group, or nil when the project has no parent group.
          # `can_be_promoted_to_epic?` treats a nil group as "not promotable", so pass it through
          # as-is instead of assuming it responds to `#group` like a Project would.
          return if quick_action_target.can_be_promoted_to_epic?(current_user, quick_action_target.container)

          error_msg(:not_found, action: 'convert')
        end

        # `filtered_types` on a project namespace excludes the Epic type when the
        # `project_epics_enabled?` feature flag is off, causing `find_work_item_type_by_name`
        # to return nil even on groups where epics are licensed. Epic promotion is a
        # group-level operation validated via `can_be_promoted_to_epic?`, so fall back to
        # the group namespace to retrieve the type object when the project-level lookup fails.
        override :find_work_item_type_by_name
        def find_work_item_type_by_name(type_name)
          type = super
          return type if type.present?

          name_str = normalize_type_name(type_name)
          return unless name_str.casecmp('epic') == 0

          group = quick_action_target.container
          return unless group

          ::WorkItems::TypesFramework::Provider.new(group).find_by_base_type(:epic)
        end

        def find_frequency(frequency)
          return unless frequency

          frequency_param = frequency.downcase.underscore
          reminder_frequencies = ::WorkItems::Progress.reminder_frequencies.keys

          reminder_frequencies.include?(frequency_param) && frequency_param
        end

        def update_progress(frequency)
          progress = quick_action_target.progress || quick_action_target.build_progress
          progress.reminder_frequency = find_frequency(frequency)

          ::SystemNoteService.change_checkin_reminder_note(quick_action_target, current_user)

          progress
        end

        override :extract_work_items
        def extract_work_items(params)
          return if params.nil?

          issues_and_work_items = super
          epics = extract_references(params, :epic)

          epics.map(&:sync_object) + issues_and_work_items
        end

        # rubocop:disable Gitlab/ModuleWithInstanceVariables -- @updates is already defined and part of
        # Gitlab::QuickActions::Dsl implementation
        override :handle_set_epic
        def handle_set_epic(parent_param)
          parent = extract_epic(parent_param)&.work_item || extract_references(parent_param, :work_item)&.first
          child = quick_action_target

          error = set_parent_validation_message(parent, child)

          @execution_message[:set_parent] = if error.nil?
                                              @updates[:epic] = parent.sync_object
                                              _('Added an issue to an epic.')
                                            else
                                              error
                                            end
        end
        # rubocop:enable Gitlab/ModuleWithInstanceVariables

        override :show_epic_alias?
        def show_epic_alias?
          # We also check that the quick action target is an instance of an issue here, since the work_item_type
          # relationship is only created after save for legacy issues
          (quick_action_target.instance_of?(::Issue) || quick_action_target.work_item_type&.issue?) &&
            quick_action_target.licensed_feature_available?(:epics)
        end
      end
    end
  end
end
