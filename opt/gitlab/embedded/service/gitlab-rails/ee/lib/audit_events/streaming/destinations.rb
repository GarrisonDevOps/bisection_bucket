# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Destinations
      BY_CATEGORY = {
        'aws' => AmazonS3StreamDestination,
        'gcp' => GoogleCloudLoggingStreamDestination,
        'http' => HttpStreamDestination
      }.freeze

      def self.for_category(category)
        BY_CATEGORY.fetch(category) do
          raise ArgumentError, "Stream destination class for category not found: #{category}"
        end
      end
    end
  end
end
