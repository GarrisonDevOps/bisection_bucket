# frozen_string_literal: true

module Vulnerabilities
  class RepresentationInformationPolicy < BasePolicy
    delegate { @subject.vulnerability.project }
  end
end
