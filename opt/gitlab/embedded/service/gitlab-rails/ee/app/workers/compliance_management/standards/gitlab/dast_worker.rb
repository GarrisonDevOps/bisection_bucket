# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Gitlab
      class DastWorker < BaseWorker
        data_consistency :delayed
        idempotent!
        urgency :low

        feature_category :compliance_management

        def service_class
          ComplianceManagement::Standards::Gitlab::DastService
        end
      end
    end
  end
end
