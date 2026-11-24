# frozen_string_literal: true

module Govern
  module PolicyEngine
    # The sentence an audit event carries for one decision. It names the
    # policy that objected and what it found for each setting.
    class ViolationMessage
      def initialize(policy:, details:)
        @policy = policy
        @details = details
      end

      def to_s
        sentence = "Settings enforcement policy '#{policy.name}' detected a violation"
        return sentence if summary.empty?

        "#{sentence}: #{summary}"
      end

      private

      attr_reader :policy, :details

      def summary
        @summary ||= details.to_a.filter_map { |detail| line_for(detail) }.join('; ')
      end

      # A custom Rego rule reports no path, only its own message.
      def line_for(detail)
        path = detail[ViolationDetails::PATH_KEY]
        return detail[ViolationDetails::MESSAGE_KEY] unless path

        [path, clause(detail, 'expected', ViolationDetails::EXPECTED_KEY),
          clause(detail, 'actual', ViolationDetails::ACTUAL_KEY)].compact.join(' ')
      end

      # Only a compliant value is worth naming, and a policy need not name one,
      # so an absent value is left out rather than read out as nil.
      def clause(detail, label, key)
        return unless detail.key?(key)

        "#{label} #{detail[key].inspect}"
      end
    end
  end
end
