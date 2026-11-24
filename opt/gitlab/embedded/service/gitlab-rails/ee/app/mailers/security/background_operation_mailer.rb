# frozen_string_literal: true

module Security
  class BackgroundOperationMailer < ApplicationMailer
    include ActionView::Helpers::TagHelper
    include ActionView::Context

    helper EmailsHelper

    layout 'mailer'

    # Regex to match "Project 'Name' (full/path)" pattern in error messages
    PROJECT_REFERENCE_PATTERN = /Project\s+'(?<name>[^']+)'\s+\((?<full_path>[^)]+)\)/

    def failure_notification(user:, operation:, failed_items:)
      @user = user
      @operation = operation.with_indifferent_access
      @failed_items = failed_items

      @humanized_operation_type = BackgroundOperationTracking.humanized_operation_type(@operation[:operation_type])

      mail(
        to: user.email,
        subject: format(_('Bulk operation failed: %{operation_type}'), operation_type: @humanized_operation_type)
      )
    end

    # Builds a clickable link for a failed item entity (Group or Project)
    # Returns HTML link if entity_full_path is present, otherwise returns a fallback text
    def entity_link_for(item)
      if item['entity_full_path'].present?
        entity_url = Gitlab::Utils.append_path(Gitlab::Routing.url_helpers.root_url, item['entity_full_path'])
        ActionController::Base.helpers.link_to(item['entity_name'] || item['entity_full_path'], entity_url)
      else
        entity_type = item['entity_type'] || 'Project'
        "#{entity_type} ID #{item['entity_id']}"
      end
    end
    helper_method :entity_link_for

    # Renders error messages for a failed item
    # Handles both single error messages and arrays of error messages
    # Returns HTML with appropriate formatting (inline for single, list for multiple)
    # Returns empty string for nil or empty input
    def render_error_messages(error_messages)
      messages = Array.wrap(error_messages)

      return '' if messages.empty?

      if messages.size == 1
        safe_join(['- ', linkify_project_references(messages.first)])
      else
        content_tag(:ul, style: 'margin: 4px 0 0 16px; padding: 0; list-style-type: none') do
          safe_join(messages.map { |msg| content_tag(:li, linkify_project_references(msg), style: 'margin: 2px 0;') })
        end
      end
    end
    helper_method :render_error_messages

    # Converts project references in error messages to clickable links
    # Input: "Project 'Security Reports' (toolbox/security-reports) has reached the maximum limit"
    # Output: "<a href='https://gitlab.com/toolbox/security-reports'>Security Reports</a> has reached the maximum limit"
    def linkify_project_references(message)
      return message if message.blank?

      parts = []
      last_end = 0

      message.to_enum(:scan, PROJECT_REFERENCE_PATTERN).each do
        match = Regexp.last_match

        # Add text before the match (will be auto-escaped by safe_join)
        parts << message[last_end...match.begin(0)] if last_end < match.begin(0)

        # Add the link (link_to returns safe HTML)
        project_name = match[:name]
        project_url = Gitlab::Utils.append_path(Gitlab::Routing.url_helpers.root_url, match[:full_path])
        parts << ActionController::Base.helpers.link_to(project_name, project_url)

        last_end = match.end(0)
      end

      # Add remaining text after last match
      parts << message[last_end..] if last_end < message.length

      safe_join(parts)
    end
    helper_method :linkify_project_references
  end
end
