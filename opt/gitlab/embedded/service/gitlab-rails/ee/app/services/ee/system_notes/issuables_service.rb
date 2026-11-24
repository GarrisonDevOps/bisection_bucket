# frozen_string_literal: true

module EE
  module SystemNotes
    module IssuablesService
      extend ::Gitlab::Utils::Override
      include ActionView::Helpers::NumberHelper

      # Called when the health_status of an Issue is changed
      #
      # Example Note text:
      #
      #   "removed the health status"
      #
      #   "changed health status to at risk"
      #
      # Returns the created Note object
      def change_health_status_note(previous_status)
        health_status = noteable.health_status&.humanize(capitalize: false)
        body = if health_status
                 "changed health status to **#{health_status}**"
               else
                 "removed health status **#{previous_status&.humanize(capitalize: false)}**"
               end

        if noteable.is_a?(Issue)
          issue_activity_counter.track_issue_health_status_changed_action(author: author, project: project)
        end

        create_note(NoteSummary.new(noteable, project, author, body, action: 'health_status'))
      end

      # Called when a custom field of type number of a WorkItem is changed
      #
      # Example Note text:
      #
      #   "changed custom_field_name to 10"
      #
      #   "removed custom_field_name: 10"
      #
      # Returns the created Note object
      def change_custom_field_number_type_note(custom_field, previous_value: nil, value: nil)
        # we are inserting HTML instead of markdown, as users can inject markdown in the custom field name
        body = if value.nil? && previous_value.present?
                 custom_field_note(custom_field.name,
                   number_with_precision(previous_value, strip_insignificant_zeros: true),
                   :removed)
               else
                 custom_field_note(custom_field.name,
                   number_with_precision(value, strip_insignificant_zeros: true),
                   :changed)
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: "custom_field"))
      end

      # Called when a custom field of type text of a WorkItem is changed
      #
      # Example Note text:
      #
      #   "changed custom_field_name to red text"
      #
      #   "removed custom_field_name: red text"
      #
      # Returns the created Note object
      def change_custom_field_text_type_note(custom_field, previous_value: nil, value: nil)
        body = if value.nil? && previous_value.present?
                 custom_field_note(custom_field.name, previous_value.strip, :removed)
               else
                 custom_field_note(custom_field.name, value.strip, :changed)
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: "custom_field"))
      end

      # Called when a custom field of type date of a WorkItem is changed
      #
      # Example Note text:
      #
      #   "changed custom_field_name to August 10, 2025"
      #
      #   "removed custom_field_name: August 10, 2025"
      #
      # Returns the created Note object
      def change_custom_field_date_type_note(custom_field, previous_value: nil, value: nil)
        body = if value.nil? && previous_value.present?
                 custom_field_note(custom_field.name, previous_value.to_fs(:long), :removed)
               else
                 custom_field_note(custom_field.name, value.to_fs(:long), :change)
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: "custom_field"))
      end

      # Called when a custom field of type select of a WorkItem is changed
      #
      # Example Note text:
      #
      #   "changed custom_field_name to red, blue"
      #
      #   "removed custom_field_name: red, blue"
      #
      # Returns the created Note object
      def change_custom_field_select_type_note(custom_field, new_options: [], previous_options: [])
        body = if new_options.blank? && previous_options.present?
                 custom_field_note(custom_field.name, previous_options.map(&:strip).join(", "), :removed)
               else
                 custom_field_note(custom_field.name, new_options.map(&:strip).join(", "), :changed)
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: "custom_field"))
      end

      # Called when the progress of a WorkItem is changed
      #
      # Example Note text:
      #
      #   "changed progress to 10%"
      #
      # Returns the created Note object
      def change_progress_note
        progress = noteable.progress&.progress

        body = if noteable.progress&.destroyed?
                 "removed the progress **#{progress}%**"
               else
                 "changed progress to **#{progress}%**"
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: 'progress'))
      end

      # Called when the color of a WorkItem is changed
      #
      # Example Note text:
      #
      #   "changed color from `#1068bf` **Blue** to `#217645` **Forest green**"
      #
      # Returns the created Note object
      def change_color_note(previous_color)
        color = noteable.color&.color&.to_s
        body = if previous_color
                 "changed color from #{color_with_swatch(previous_color)} to #{color_with_swatch(color)}"
               elsif noteable.color&.destroyed?
                 "removed color #{color_with_swatch(color)}"
               else
                 "set color to #{color_with_swatch(color)}"
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: 'color'))
      end

      # Called when the reminder_frequency of a WorkItemProgress is changed
      #
      # Example Note text:
      #
      #   "set a weekly checkin reminder"
      #
      # Returns the created Note object
      def change_checkin_reminder_note
        cadence = noteable.progress&.reminder_frequency

        body = if cadence == 'never'
                 "removed the checkin reminder"
               else
                 "set a **#{cadence.humanize(capitalize: false)}** checkin reminder"
               end

        create_note(NoteSummary.new(noteable, project, author, body, action: 'checkin_reminder'))
      end

      WORKPLAN_NOTE_BODIES = {
        added: 'added a workplan',
        updated: 'updated the workplan',
        removed: 'removed the workplan'
      }.freeze

      def change_workplan_note(change)
        body = WORKPLAN_NOTE_BODIES.fetch(change)

        create_note(NoteSummary.new(noteable, project, author, body, action: 'workplan'))
      end

      # Called when the an issue is published to a project's
      # status page application
      #
      # Example Note text:
      #
      #   "published this issue to the status page"
      #
      # Returns the created Note object
      def publish_issue_to_status_page
        body = 'published this issue to the status page'

        create_note(NoteSummary.new(noteable, project, author, body, action: 'published'))
      end

      # Called when an issuable is linked as blocking
      #
      # noteable_ref - Referenced noteable object, or array of objects
      #
      # Example Note text:
      #
      #   "marked this item as blocking gitlab-foss#9001"
      #   "marked this item as blocking gitlab-foss#9001 and gitlab-foss#9002"
      #   "marked this item as blocking &9"
      #   "marked this item as blocking &9, &10, and &11"
      #
      # Returns the created Note object
      def block_issuable(noteable_ref)
        body = block_message(noteable_name, extract_issuable_reference(noteable_ref), 'blocking')

        create_note(NoteSummary.new(noteable, project, author, body, action: 'relate'))
      end

      # Called when an issuable is linked as a blocked by
      #
      # noteable_ref - Referenced noteable object, or array of objects
      #
      # Example Note text:
      #
      #   "marked this item as blocked by gitlab-foss#9001"
      #   "marked this item as blocked by gitlab-foss#9001 and gitlab-foss#9002"
      #   "marked this item as blocked by &9"
      #   "marked this item as blocked by &9, &10, and &11"
      #
      # Returns the created Note object
      def blocked_by_issuable(noteable_ref)
        body = block_message(noteable_name, extract_issuable_reference(noteable_ref), 'blocked by')

        create_note(NoteSummary.new(noteable, project, author, body, action: 'relate'))
      end

      override :track_cross_reference_action
      def track_cross_reference_action
        super

        return unless noteable.is_a?(Epic)

        counter = ::Gitlab::UsageDataCounters::EpicActivityUniqueCounter

        counter.track_epic_cross_referenced(author: author, namespace: noteable.group)
      end

      override :cross_reference_disallowed?
      def cross_reference_disallowed?(mentioned_in)
        epic_self_reference?(mentioned_in) || super
      end

      # Called when an Amazon Q command is successfully sent to the AI gateway
      #
      # noteable_ref - Referenced noteable object
      # event - The type of command executed by the user
      #
      # Example Note text:
      #
      #   "sent dev request to Amazon Q"
      #
      # Returns the created Note object
      def amazon_q_called(event)
        body = "sent #{event} request to Amazon Q"

        create_note(NoteSummary.new(noteable, project, author, body, action: 'notify_service'))
      end

      # Called when the status of a work item is changed
      #
      # Example Note text:
      #
      #   "set status to `Done`"
      #
      # Returns the created Note object
      def change_work_item_status(status)
        body = format("set status to **%{status_name}**", status_name: status.name)

        create_note(NoteSummary.new(noteable, project, author, body, action: 'work_item_status'))
      end

      private

      def color_with_swatch(hex)
        "`#{hex}` **#{color_name_for(hex)}**"
      end

      def color_name_for(hex)
        ::WorkItems::Color::COLOR_HEX_TO_NAME[hex&.downcase] || 'Custom'
      end

      def block_message(issuable_type, noteable_reference, type)
        "marked this #{issuable_type} as #{type} #{noteable_reference}"
      end

      def epic_self_reference?(mentioned_in)
        noteable.is_a?(Epic) &&
          (mentioned_in.is_a?(Issue) || mentioned_in.is_a?(WorkItem)) &&
          noteable == mentioned_in&.synced_epic
      end

      def custom_field_note(name, value, action)
        name = ERB::Util.html_escape(name)
        value = ERB::Util.html_escape(value)

        if action == :removed
          "<p>removed #{name}: <code class=\"idiff\">#{value}</code></p>"
        else
          "<p>changed #{name} to <code class=\"idiff\">#{value}</code></p>"
        end
      end
    end
  end
end
