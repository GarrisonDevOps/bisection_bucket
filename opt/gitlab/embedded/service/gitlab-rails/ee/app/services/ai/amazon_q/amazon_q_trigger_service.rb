# frozen_string_literal: true

module Ai
  module AmazonQ
    class AmazonQTriggerService < BaseService
      include ::Gitlab::Utils::StrongMemoize

      CloudConnectorTokenError = Class.new(StandardError)
      ServiceAccountError = Class.new(StandardError)
      CompositeIdentityEnforcedError = Class.new(StandardError)
      MissingPrerequisiteError = Class.new(StandardError)

      REVIEW_FINDING_KEYWORDS = ["We detected", "We recommend", "Severity:"].freeze
      EVENT_ID = "Quick Action"

      def initialize(user:, command:, source:, note: nil, discussion_id: nil, input: nil)
        @user = user
        @command = command
        @input = input
        @source = source
        @note = note
        @discussion_id = discussion_id
      end

      attr_reader :user, :command, :source, :note, :discussion_id, :input

      def execute
        validate_service_account!
        validate_source!

        add_service_account_to_project

        SystemNoteService.amazon_q_called(source, user, command)
        create_note_if_needed

        response = make_ai_gateway_request
        handle_response(response)
        response
      rescue StandardError => e
        Gitlab::ErrorTracking.log_exception(e)
        handle_note_error(e.message)
      end

      private

      def make_ai_gateway_request
        client = Gitlab::Llm::QAi::Client.new(user)

        client.create_event(
          payload: payload,
          role_arn: ai_settings.amazon_q_role_arn,
          event_id: EVENT_ID
        )
      end

      def handle_response(response)
        return if response.success?

        update_failure_note(response.parsed_response)
      end

      def payload
        ::Ai::AmazonQ::RequestPayload.new(
          command: command,
          source: source,
          note: note,
          service_account_notes: service_account_notes,
          discussion_id: discussion_id,
          input: input,
          line_position_for_comment: line_position_for_comment
        ).payload
      end
      strong_memoize_attr :payload

      def validate_source!
        Ai::AmazonQValidateCommandSourceService.new(command: command, source: source).validate
      end

      def use_existing_thread?
        %w[dev review transform].include?(command)
      end

      def create_note_if_needed
        return if use_existing_thread?

        create_note
      end

      def line_position_for_comment
        return unless note&.position

        if note.position.line_range.present?
          {
            comment_start_line: note.position.line_range.dig("start", "new_line").to_s,
            comment_end_line: note.position.line_range.dig("end", "new_line").to_s
          }
        elsif note.position.new_line.present?
          {
            comment_start_line: note.position.new_line.to_s,
            comment_end_line: note.position.new_line.to_s
          }
        end
      end
      strong_memoize_attr :line_position_for_comment

      def create_note
        @progress_note = ::Ai::AmazonQ::CreateNoteService.new(
          author: amazon_q_service_account,
          note: note,
          source: source,
          command: command
        ).execute
      end

      def update_failure_note(error_string = nil)
        if @progress_note.nil?
          @progress_note = ::Notes::CreateService.new(
            source.project,
            amazon_q_service_account,
            author: amazon_q_service_account,
            noteable: source,
            note: failure_message(error_string),
            discussion_id: note&.discussion_id
          ).execute
        else
          update_note_params = { note: failure_message(error_string) }

          ::Notes::UpdateService.new(
            source.project,
            amazon_q_service_account,
            update_note_params
          ).execute(@progress_note)
        end
      end

      def failure_message(error_string = nil)
        request_id = Labkit::Correlation::CorrelationId.current_id

        # Check if this is a ResourceNotFoundException error
        base_message = if resource_not_found_error?(error_string)
                         format(
                           s_('AmazonQ|Your Amazon Q connection is missing or has been deleted. ' \
                             "You'll need to reconnect to use this feature. " \
                             'Please see [Set up GitLab Duo with Amazon Q](%{setup_url}) ' \
                             'for how to reconnect your Amazon Q developer plugin.'),
                           setup_url: Rails.application.routes.url_helpers.help_page_url(
                             'user/duo_amazon_q/setup.md', anchor: 'set-up-gitlab-duo-with-amazon-q'
                           )
                         )
                       else
                         s_("AmazonQ|Sorry, I'm not able to complete the request at this moment. " \
                           'Please try again later.')
                       end

        request_id_message = format(s_("AmazonQ|Request ID: %{request_id}"), request_id: request_id)

        message_parts = ["> [!warning]", ">", "> #{base_message}", ">", "> #{request_id_message}"]

        if error_string.present?
          error_message = format(_('Error: %{error_message}'), error_message: error_string)
          message_parts.concat([">", "> #{error_message}"])
        end

        message_parts.join("\n")
      end

      # Detects if the error is related to Amazon Q ResourceNotFoundException
      # This typically occurs when the Amazon Q connection is missing or deleted
      def resource_not_found_error?(error_string)
        return false if error_string.blank?

        error_message = error_string.is_a?(Hash) ? error_string.to_s : error_string

        error_message.include?('ResourceNotFoundException') &&
          error_message.include?('SendEvent operation')
      end

      def amazon_q_service_account
        Ai::Setting.for_organization_read_only(source.project.organization).amazon_q_service_account_user
      end
      strong_memoize_attr :amazon_q_service_account

      def validate_service_account!
        if amazon_q_service_account.blank?
          raise ServiceAccountError,
            "#{command} failed due to Amazon Q service account ID is not configured"
        elsif !amazon_q_service_account.composite_identity_enforced?
          raise CompositeIdentityEnforcedError,
            "Cannot find the service account with composite identity enabled"
        end

        true
      end

      def add_service_account_to_project
        ::Ai::ServiceAccountMemberAddService.new(source.project, amazon_q_service_account).execute
      end

      def search_comments_by_service_account(keywords = nil)
        filtered_notes = service_account_notes

        return filtered_notes if keywords.blank?

        keywords = Array(keywords).map(&:downcase)

        filtered_notes.select do |note|
          note_content = note.note.to_s.downcase
          keywords.any? { |keyword| note_content.include?(keyword) }
        end
      end

      def handle_note_error(error_message)
        return unless note

        note.errors.add(:quick_action, "command /q: #{error_message}")
      end

      def service_account_notes
        source.notes.authored_by(amazon_q_service_account).find_discussion(discussion_id)&.notes.to_a
      end
      strong_memoize_attr :service_account_notes
    end
  end
end
