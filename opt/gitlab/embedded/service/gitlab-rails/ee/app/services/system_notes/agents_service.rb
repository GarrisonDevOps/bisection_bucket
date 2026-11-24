# frozen_string_literal: true

module SystemNotes # rubocop:disable Gitlab/BoundedContexts -- SystemNotes module already exists and holds the other services
  class AgentsService < ::SystemNotes::BaseService
    # Called when a new agent session is started
    #
    # session_id - The ID of the agent session
    # trigger_source - Who/what triggered the session. Can be a User object or a String (default: 'User')
    # service_account_user - The service account user executing the workflow (optional).
    #   When nil, no system note is created since Note requires a valid author.
    #
    # Example Note text:
    #
    # "started session [123](session_url) triggered by @jane_doe"
    #
    # Returns the created Note object, or nil if no valid author is available
    def agent_session_started(session_id, trigger_source, service_account_user)
      author = agent_author(service_account_user)
      return unless author

      session_link = create_session_link(session_id)
      trigger_source_reference = format_trigger_source(trigger_source)

      body = "started session #{session_link}"

      body += " triggered by #{trigger_source_reference}" if trigger_source.present?

      create_note(NoteSummary.new(
        noteable,
        project,
        author,
        body,
        action: 'duo_agent_started'
      ))
    end

    # Called when a Duo agent session is completed
    #
    # session_id - The ID of the agent session
    # service_account_user - The service account user executing the workflow (optional).
    #   When nil, no system note is created since Note requires a valid author.
    #
    # Example Note text:
    #
    # "completed session [123](session_url)"
    #
    # Returns the created Note object, or nil if no valid author is available
    def agent_session_completed(session_id, service_account_user)
      author = agent_author(service_account_user)
      return unless author

      session_link = create_session_link(session_id)

      body = "completed session #{session_link}"

      create_note(NoteSummary.new(
        noteable,
        project,
        author,
        body,
        action: 'duo_agent_completed'
      ))
    end

    # Called when a Duo agent session fails
    #
    # workflow - The failed session
    # service_account_user - The service account user executing the workflow (optional).
    #   When nil, no system note is created since Note requires a valid author.
    #
    # Example Note text:
    #
    # "Developer failed session [123](session_url)", followed by a middle dot and the cause when there is one
    #
    # Returns the created Note object, or nil if no valid author is available
    def agent_session_failed(workflow, service_account_user)
      cause = ::Gitlab::I18n.with_default_locale { workflow.failure_cause }

      create_session_end_note(workflow, service_account_user, 'failed', cause, 'duo_agent_failed')
    end

    # Called when a Duo agent session is stopped
    #
    # Example Note text:
    #
    # "Developer stopped session [123](session_url)"
    #
    # Returns the created Note object, or nil if no valid author is available
    def agent_session_stopped(workflow, service_account_user)
      create_session_end_note(workflow, service_account_user, 'stopped', nil, 'duo_agent_stopped')
    end

    private

    # The note is stored once, so it is written in the default language, not the acting user's.
    def create_session_end_note(workflow, service_account_user, state, cause, action)
      author = agent_author(service_account_user)
      return unless author

      session_link = create_session_link(workflow.id)
      flow_name = ::Gitlab::I18n.with_default_locale { session_flow_name(workflow) }
      body = session_end_text(flow_name, state, session_link)
      body += " · #{cause}" if cause.present?

      create_note(NoteSummary.new(noteable, project, author, body, action: action))
    end

    def session_end_text(flow_name, state, session_link)
      return "session #{session_link} #{state}" if flow_name.blank?

      escaped_name = ::GLFMMarkdown.escape_commonmark_inline(flow_name).gsub(/[@%$^]/) { |char| "\\#{char}" }
      "#{escaped_name} #{state} session #{session_link}"
    end

    def session_flow_name(workflow)
      workflow.foundational_flow&.translated_display_name ||
        workflow.ai_catalog_item_version&.item&.name
    end

    def agent_author(service_account_user)
      return service_account_user if service_account_user&.service_account?

      nil
    end

    def create_session_link(session_id)
      session_id = ERB::Util.html_escape(session_id)

      return session_id.to_s unless project

      session_url = "#{project.web_url}/-/automate/agent-sessions/#{session_id}"

      "[#{session_id}](#{session_url})"
    end

    # Formats a trigger source into a user reference or escaped string.
    #
    # For User objects this emits a `@username` reference (the same form
    # "requested review from @user" notes use) so Banzai renders it as a
    # linked user mention with the member popover, rather than a plain
    # full-name profile link.
    #
    # @param trigger_source [User, String] The trigger source to format
    # @return [String] User reference (@username) for User objects, escaped string otherwise
    #
    # Examples:
    #   format_trigger_source(user)     # => "@jane_doe"
    #   format_trigger_source("agent") # => "agent"
    def format_trigger_source(trigger_source)
      if trigger_source.is_a?(User)
        trigger_source.to_reference
      else
        ERB::Util.html_escape(trigger_source.to_s)
      end
    end
  end
end
