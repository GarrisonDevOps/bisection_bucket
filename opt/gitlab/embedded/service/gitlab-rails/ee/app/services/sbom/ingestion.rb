# frozen_string_literal: true

module Sbom
  module Ingestion
    def self.project_lease_key(project_id)
      "#{name.underscore}:projects:#{project_id}"
    end
  end
end
