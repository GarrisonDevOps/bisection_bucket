# frozen_string_literal: true

module Security
  module Ascp
    class SecurityContext < ::SecApplicationRecord
      include StripAttribute

      self.table_name = 'ascp_security_contexts'

      SECURITY_BOUNDARIES = %w[
        NETWORK_ACCESS
        USER_INPUT
        PARTNER_BOUNDARY
        TRUSTED_SERVICE
        INTERNAL_ONLY
        ISOLATED
      ].freeze

      belongs_to :project
      belongs_to :scan, class_name: 'Security::Ascp::Scan'
      belongs_to :component, class_name: 'Security::Ascp::Component', inverse_of: :security_context

      has_many :guidelines, class_name: 'Security::Ascp::SecurityGuideline', inverse_of: :security_context

      strip_attributes! :summary, :authentication_model, :authorization_model, :data_sensitivity

      validates :project, :scan, :component, presence: true
      validates :component_id, uniqueness: { scope: [:project_id, :scan_id] }
      validates :summary, length: { maximum: 4096 }
      validates :authentication_model, length: { maximum: 1024 }
      validates :authorization_model, length: { maximum: 1024 }
      validates :data_sensitivity, length: { maximum: 255 }
      validates :security_boundary, inclusion: { in: SECURITY_BOUNDARIES }

      scope :at_scan, ->(scan_id) { where(scan_id: scan_id) }
    end
  end
end
