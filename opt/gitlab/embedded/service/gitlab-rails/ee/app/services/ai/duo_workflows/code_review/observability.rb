# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      module Observability
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::InternalEventsTracking

        UNIT_PRIMITIVE = 'review_merge_request'

        private

        def error(message = nil, payload = {})
          ServiceResponse.error(message: message, payload: payload)
        end

        def track_review_merge_request_event(event_name, attributes = {})
          track_internal_event(
            event_name,
            attributes.reverse_merge(
              user: user,
              project: merge_request.project
            )
          )
        end

        def track_review_merge_request_exception(error, context = {})
          Gitlab::ErrorTracking.track_exception(
            error,
            context.reverse_merge(
              unit_primitive: UNIT_PRIMITIVE
            )
          )
        end

        def log_review_merge_request_event(attributes = {})
          return unless review_merge_request_logging_enabled?

          Gitlab::AppLogger.info(
            attributes.reverse_merge(unit_primitive: UNIT_PRIMITIVE)
          )
        end

        def review_merge_request_logging_enabled?
          Feature.enabled?(:duo_code_review_response_logging, user)
        end
        strong_memoize_attr :review_merge_request_logging_enabled?
      end
    end
  end
end
