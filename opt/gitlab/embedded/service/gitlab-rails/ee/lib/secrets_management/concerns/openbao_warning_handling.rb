# frozen_string_literal: true

module SecretsManagement
  module Concerns
    module OpenbaoWarningHandling
      extend ActiveSupport::Concern

      WarningError = Class.new(StandardError)

      included do
        def block_action_due_to_unknown_warning?
          Gitlab.dev_or_test_env? || Gitlab.staging?
        end
      end

      SAFE_WARNING_PATTERNS = [
        [/endpoint replaced the value of these parameters.*captured from the endpoint's path/i, nil],
        [/(ttl|max_ttl|period).*greater.*(default|maximum).*will be truncated/i, nil],
        [/deprecated/i, nil],
        [/requested namespace does not exist/i, %i[get list scan delete]],
        [/Tidy operation (successfully started|already in progress)/i, nil]
      ].freeze

      CRITICAL_WARNING_PATTERNS = [
        [/namespace .* (not found|disabled)/i, nil],
        [/(mount|path).*misconfig/i, nil],
        [/ignored these unrecognized parameters/i, nil],
        [/requested namespace does not exist/i, %i[post put patch]]
      ].freeze

      # Public: call this from the client after parsing response body.
      def handle_openbao_warnings!(body, endpoint:, namespace: nil, method: nil)
        return unless body.is_a?(Hash) && body["warnings"].present?

        warnings = Array(body["warnings"]).map { |w| w.to_s.strip }.reject(&:empty?)
        return if warnings.empty?

        categories = categorize_openbao_warnings(warnings, method)

        # The raw path ends in a user-chosen secret name, and neither Sentry's
        # extra payload nor the log filter scrubs it: both match on key names.
        operation = ::Gitlab::Instrumentation::Openbao.operation_for(endpoint)

        Gitlab::AppLogger.warn(
          ::Labkit::Fields::LOG_MESSAGE => "[OpenBao] warnings",
          operation: operation,
          namespace: namespace,
          warning_source: 'Openbao',
          safe_warnings: categories[:safe_warnings],
          critical_warnings: categories[:critical_warnings],
          unknown_warnings: categories[:unknown_warnings]
        )

        must_block = categories[:critical_warnings].any? ||
          (block_action_due_to_unknown_warning? && categories[:unknown_warnings].any?)
        return unless must_block

        msgs = (categories[:critical_warnings] +
          (block_action_due_to_unknown_warning? ? categories[:unknown_warnings] : []))

        exception = WarningError.new(msgs.join('; '))

        Gitlab::ErrorTracking.track_and_raise_exception(
          exception,
          subsystem: "openbao",
          operation: operation,
          method: method&.to_s,
          namespace: namespace,
          safe_warnings: categories[:safe_warnings],
          critical_warnings: categories[:critical_warnings],
          unknown_warnings: categories[:unknown_warnings]
        )
      end

      private

      def categorize_openbao_warnings(list, method = nil)
        categories = {
          safe_warnings: [],
          critical_warnings: [],
          unknown_warnings: []
        }

        safe_patterns = SAFE_WARNING_PATTERNS
        critical_patterns = CRITICAL_WARNING_PATTERNS

        list.each do |warning|
          next if warning.blank?

          # rubocop:disable Cop/LineBreakAroundConditionalBlock -- Not a justified complaint
          categories[
            if matches_pattern?(warning, method, safe_patterns)
              :safe_warnings
            elsif matches_pattern?(warning, method, critical_patterns)
              :critical_warnings
            else
              :unknown_warnings
            end
          ] << warning
          # rubocop:enable Cop/LineBreakAroundConditionalBlock
        end

        categories
      end

      def matches_pattern?(warning, method, patterns)
        patterns.any? do |regex, allowed_methods|
          (allowed_methods.nil? || method.nil? || allowed_methods.include?(method)) &&
            regex.match?(warning)
        end
      end
    end
  end
end
