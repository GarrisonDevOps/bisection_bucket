# frozen_string_literal: true

module Security
  class SyncLicenseScanningRulesService
    def self.execute(pipeline)
      new(pipeline).execute
    end

    def initialize(pipeline)
      @pipeline = pipeline
    end

    def execute
      pipeline.opened_merge_requests_with_head_sha.each do |merge_request|
        Security::ScanResultPolicies::UpdateLicenseApprovalsService.new(merge_request, pipeline).execute
      end
    end

    private

    attr_reader :pipeline
  end
end
