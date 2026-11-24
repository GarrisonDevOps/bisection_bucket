# frozen_string_literal: true

module EE
  module Users
    module AutoBanService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        send_truth_data

        super
      end

      override :execute!
      def execute!
        send_truth_data

        super
      end

      private

      def send_truth_data
        return unless ::Gitlab::Saas.feature_available?(:identity_verification)

        Arkose::TruthDataService.new(user: user, is_legit: false).execute
      end
    end
  end
end
