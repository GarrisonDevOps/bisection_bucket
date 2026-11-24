# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class AgentEventParser
        include ::Gitlab::Llm::Concerns::Logger

        def parse(event_json)
          begin
            event = Gitlab::Json.safe_parse(event_json) if event_json.is_a?(String)
          rescue JSON::ParserError
            # no-op
          end

          unless event && event['type'].present?
            # Possibilities:
            # 1. AI Gateway issue ... Event data was sent from AI Gateway, but it's corrupted (e.g. not JSON).
            # 2. GitLab-Rails issue ... Event data was sent from AI Gateway correctly,
            #    but the data is split abruptly by Net::BufferedIo.
            log_warn(message: "Failed to parse a chunk from Duo Chat Agent", event_json_size: event_json.length,
              event_name: 'parsing_error', ai_component: 'duo_chat')
            return
          end

          begin
            klass = "Gitlab::Duo::Chat::AgentEvents::#{event['type'].camelize}".constantize
            klass.new(event["data"])
          rescue NameError
            # Make sure that the v2/chat/agent endpoint in AI Gateway and the GitLab-Rails are compatible.
            log_error(message: "Failed to find the event class in GitLab-Rails.", event_type: event['type'],
              event_name: 'parsing_error',
              ai_component: 'duo_chat')
            nil
          end
        end
      end
    end
  end
end
