# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class ApprovalReportTypeEnum < BaseEnum
      graphql_name 'ApprovalReportType'

      value 'SCAN_FINDING',
        value: 'scan_finding',
        description: 'Represents report_type for vulnerability check related approval rules.'

      value 'LICENSE_SCANNING',
        value: 'license_scanning',
        description: 'Represents report_type for license scanning related approval rules.'

      value 'ANY_MERGE_REQUEST',
        value: 'any_merge_request',
        description: 'Represents report_type for any_merge_request related approval rules.'
    end
  end
end
