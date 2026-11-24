# frozen_string_literal: true

module Security
  module Ascp
    class SecurityGuideline < ::SecApplicationRecord
      include StripAttribute

      self.table_name = 'ascp_security_guidelines'

      belongs_to :project
      belongs_to :scan, class_name: 'Security::Ascp::Scan'
      belongs_to :security_context, class_name: 'Security::Ascp::SecurityContext', inverse_of: :guidelines

      strip_attributes! :name, :operation, :legitimate_use, :security_boundary, :business_context

      validates :project, :scan, :security_context, :name, :operation, presence: true
      validates :name, length: { maximum: 255 }
      validates :operation, length: { maximum: 1024 }
      validates :legitimate_use, length: { maximum: 4096 }
      validates :security_boundary, length: { maximum: 4096 }
      validates :business_context, length: { maximum: 4096 }

      # Inline enum - DO NOT use Enums::Ascp module
      enum :severity_if_violated, { low: 0, medium: 1, high: 2, critical: 3 }

      scope :at_scan, ->(scan_id) { where(scan_id: scan_id) }
    end
  end
end
