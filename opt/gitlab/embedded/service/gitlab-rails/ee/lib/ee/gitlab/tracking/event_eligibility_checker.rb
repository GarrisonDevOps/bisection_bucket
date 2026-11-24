# frozen_string_literal: true

module EE
  module Gitlab
    module Tracking
      module EventEligibilityChecker
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        EXTERNAL_DUO_EVENTS = {
          'gitlab_ide_extension' => %w[
            click_button
            message_sent
            open_quick_chat
            shortcut
            suggestion_accepted
            suggestion_cancelled
            suggestion_error
            suggestion_loaded
            suggestion_not_provided
            suggestion_rejected
            suggestion_request_rejected
            suggestion_requested
            suggestion_shown
            suggestion_stream_completed
            suggestion_stream_started
          ]
        }.freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :internal_duo_events
          def internal_duo_events
            @internal_duo_events ||= ::Gitlab::Tracking::EventDefinition.definitions.filter_map do |definition|
              definition.action if definition.duo_event?
            end.to_set + super
          end

          override :send_frontend_events?
          def send_frontend_events?
            super || internal_duo_events.any?
          end
        end

        override :eligible?
        def eligible?(event, app_id = nil)
          super || eligible_duo_event?(event, app_id)
        end

        private

        def eligible_duo_event?(event_name, app_id)
          duo_event = if external_service?(app_id)
                        external_duo_event?(event_name, app_id)
                      else
                        self.class.internal_duo_events.include?(event_name)
                      end

          duo_event && !::Ai::Setting.self_hosted?
        end

        def external_service?(app_id)
          EXTERNAL_DUO_EVENTS.has_key?(app_id)
        end

        def external_duo_event?(event_name, app_id)
          EXTERNAL_DUO_EVENTS[app_id]&.include?(event_name)
        end
      end
    end
  end
end
