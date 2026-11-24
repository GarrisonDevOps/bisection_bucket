# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Gitlab
      class SastWorker < BaseWorker
        data_consistency :delayed
        idempotent!
        urgency :low

        feature_category :compliance_management

        def service_class
          ComplianceManagement::Standards::Gitlab::SastService
        end
      end
    end
  end
end
