# frozen_string_literal: true

module Vulnerabilities
  class FindingTokenStatusPolicy < BasePolicy
    delegate { @subject.finding.vulnerability }

    condition(:read_vulnerability) { can?(:read_vulnerability, @subject.project) }

    rule { read_vulnerability }.policy do
      enable :read_finding_token_status
    end
  end
end
