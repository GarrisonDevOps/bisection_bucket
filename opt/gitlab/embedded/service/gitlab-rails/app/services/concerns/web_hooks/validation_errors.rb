# frozen_string_literal: true

module WebHooks
  # Shared mapping of hook validation errors to service error responses, so the
  # create and update paths return identical messages to the API and UI.
  module ValidationErrors
    # Errors that do not match a specific message below are flagged with this
    # reason so API callers can render the structured `hook.errors` body
    # (`render_validation_error!`) instead of the flattened sentence.
    GENERIC_VALIDATION_FAILURE = :validation_failed

    private

    def validation_error(hook)
      return error("Invalid url given", 422) if hook.errors[:url].present?
      return error("Invalid branch filter given", 422) if hook.errors[:push_events_branch_filter].present?

      if hook.errors[:custom_headers].present?
        return error("Custom headers validation failed: #{hook.errors[:custom_headers].join(', ')}", 422)
      end

      ServiceResponse.error(
        message: hook.errors.full_messages.to_sentence,
        http_status: 422, # rubocop:disable Gitlab/ServiceResponse -- same status the `error` calls above set, so direct readers of http_status get one
        reason: GENERIC_VALIDATION_FAILURE
      )
    end
  end
end
