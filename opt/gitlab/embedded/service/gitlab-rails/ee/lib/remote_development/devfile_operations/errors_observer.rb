# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class ErrorsObserver
      extend Gitlab::Fp::MessageSupport

      # @param [RemoteDevelopment::Message] message
      # @return [void]
      def self.observe(message)
        message.content => {
          context: {
            user: user,
            internal_events_class: internal_events_class,
          }
        }

        internal_events_class.track_event("devfile_validate_result", category: name, user: user,
          additional_properties: { label: "failed", property: message.class.name.demodulize })

        nil
      end
    end
  end
end
