# frozen_string_literal: true

module Mutations
  module Ai
    class DuoUserFeedback < BaseMutation
      graphql_name 'DuoUserFeedback'

      include Routing::PseudonymizationHelper

      argument :ai_message_id, GraphQL::Types::String, required: true, description: 'ID of the AI Message.'
      argument :tracking_event, ::Types::Tracking::EventInputType, required: false, description: 'Tracking event data.'

      authorize_granular_token permissions: :create_duo_user_feedback,
        boundary: :user, boundary_type: :user

      def resolve(**args)
        raise_resource_not_available_error! unless current_user

        message = ::Ai::Conversation::Message.find_for_user!(args[:ai_message_id], current_user)

        message.update!(has_feedback: true)

        track_snowplow_event(args[:tracking_event], message)

        { errors: [] }
      rescue ActiveRecord::RecordNotFound
        raise_resource_not_available_error!
      end

      private

      def track_snowplow_event(event, message)
        return unless event

        extra = event.extra.is_a?(Hash) ? event.extra.slice('improveWhat', 'didWhat', 'promptLocation') : {}

        Gitlab::Tracking.event(
          event.category,
          event.action,
          user: current_user,
          label: event.label,
          property: event.property,
          requestId: message.request_id,
          cleanedUrl: cleaned_url,
          **extra
        )
      end

      def cleaned_url
        url = context[:request].headers["Referer"]

        # Pseudo-anonymize the URL to remove identifiable information
        url = masked_referrer_url(url)

        return unless url

        uri = URI.parse(url)
        path = uri.path

        # Remove all numbers, as they do not provide any value
        path = path.gsub(/\d+/, '')

        # Remove repetitive slashes
        path.squeeze('/')
      end
    end
  end
end
