# frozen_string_literal: true

module EE
  module Issues
    module LookAheadPreloads
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :preloads
      def preloads
        super.merge(
          {
            epic: [:epic],
            sla_due_at: [:issuable_sla],
            metric_images: [:metric_images],
            related_vulnerabilities: :related_vulnerabilities,
            status: [:namespace, { current_status: :custom_status }]
          }
        )
      end
    end
  end
end
