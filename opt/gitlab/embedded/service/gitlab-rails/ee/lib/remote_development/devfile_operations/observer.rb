# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class Observer
      extend Gitlab::Fp::MessageSupport

      # @param [Hash] context
      # @return [void]
      def self.observe(context)
        context => {
          user: user,
          internal_events_class: internal_events_class
        }

        internal_events_class.track_event("devfile_validate_result", category: name, user: user,
          additional_properties: { label: "succeed" })

        nil
      end
    end
  end
end
