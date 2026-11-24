# frozen_string_literal: true

module Vulnerabilities
  module Archival
    def self.enabled_for?(project)
      ::Feature.enabled?(:vulnerability_archival, project.namespace) ||
        ::Feature.enabled?(:vulnerability_archival, project.root_ancestor)
    end
  end
end
