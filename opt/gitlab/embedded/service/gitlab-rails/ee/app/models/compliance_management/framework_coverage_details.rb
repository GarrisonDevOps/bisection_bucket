# frozen_string_literal: true

module ComplianceManagement
  class FrameworkCoverageDetails
    include GlobalID::Identification

    attr_reader :framework

    delegate_missing_to :framework

    def initialize(framework)
      @framework = framework
    end
  end
end
