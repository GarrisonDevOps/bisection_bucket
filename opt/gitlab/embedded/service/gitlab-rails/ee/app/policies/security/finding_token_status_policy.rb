# frozen_string_literal: true

module Security
  class FindingTokenStatusPolicy < BasePolicy
    delegate { @subject.security_finding }

    condition(:read_vulnerability) { can?(:read_vulnerability, @subject.project) }

    rule { read_vulnerability }.policy do
      enable :read_finding_token_status
    end
  end
end
