# frozen_string_literal: true

module Vulnerabilities
  class ChangesTrackingService
    include Gitlab::InternalEventsTracking
    include Gitlab::Utils::StrongMemoize

    EVENT_LABEL = 'vulnerability_change'
    TRACKING_STATUS = { success: 'success', error: 'error' }.freeze

    def initialize(user:, category:, vulnerabilities:, new_value:, field:, error: nil)
      @user = user
      @category = category
      @vulnerabilities = vulnerabilities
      @new_value = new_value
      @field = field&.to_s
      @error = error
    end

    def execute
      return error_missing_required_attributes_response unless missing_attributes.empty?
      return error_invalid_vulnerabilities_response unless vulnerabilities.all?(::Vulnerability)

      track_all_vulnerability_updates

      return error_tracking_response if tracking_error
      return error_no_trackable_vulnerabilities_response if tracked.empty?

      success_tracking_response
    end

    private

    attr_reader :user, :category, :vulnerabilities, :new_value, :field, :error, :tracked, :tracking_error

    def missing_attributes
      required_attributes.select { |_, value| value.nil? }.keys
    end
    strong_memoize_attr :missing_attributes

    def required_attributes
      {
        user: user,
        category: category,
        vulnerabilities: vulnerabilities,
        new_value: new_value,
        field: field
      }
    end

    def track_all_vulnerability_updates
      @tracked = []
      @tracking_error = nil

      vulnerabilities.each do |vulnerability|
        track_vulnerability_update(vulnerability)
        tracked << vulnerability
      rescue StandardError => e
        @tracking_error = e
        break
      end
    end

    def track_vulnerability_update(vulnerability)
      track_internal_event(
        "vulnerability_changed",
        user: user,
        project: vulnerability.project,
        namespace: vulnerability.project.namespace,
        category: category,
        additional_properties: build_tracking_payload(vulnerability)
      )
    end

    def build_tracking_payload(vulnerability)
      {
        vulnerability_id: vulnerability.id,
        old_value: vulnerability.attributes[field].as_json,
        new_value: new_value.as_json,
        property: error ? TRACKING_STATUS[:error] : TRACKING_STATUS[:success],
        label: "#{EVENT_LABEL}_#{field}",
        field: field,
        error_message: error&.message
      }.compact
    end

    def success_tracking_response
      ServiceResponse.success(payload: { vulnerabilities: tracked })
    end

    def error_tracking_response
      error_response(
        format(
          s_('Vulnerabilities|Internal tracking failed: %{message}'),
          message: tracking_error.message
        ),
        payload: { vulnerabilities: tracked }
      )
    end

    def error_missing_required_attributes_response
      error_response(
        format(
          s_('Vulnerabilities|Missing required attributes: %{attributes}'),
          attributes: missing_attributes.join(', ')
        )
      )
    end

    def error_no_trackable_vulnerabilities_response
      error_response(s_('Vulnerabilities|No valid vulnerabilities to track'))
    end

    def error_invalid_vulnerabilities_response
      error_response(s_('Vulnerabilities|All records must be instances of Vulnerability'))
    end

    def error_response(message, payload: {})
      ServiceResponse.error(message: message, payload: payload)
    end
  end
end
