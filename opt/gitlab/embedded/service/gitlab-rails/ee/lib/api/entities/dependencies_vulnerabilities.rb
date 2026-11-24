# frozen_string_literal: true

module API
  module Entities
    class DependenciesVulnerabilities < Grape::Entity
      expose :occurrence_id, documentation: { type: 'Integer', format: 'int64' } do |_, options|
        options[:occurrence_id]
      end

      expose :id, documentation: { type: 'Integer', format: 'int64' }

      expose :name, documentation: { type: 'String' } do |vulnerability|
        vulnerability.finding.name
      end

      expose :url, documentation: { type: 'String' } do |vulnerability, options|
        vulnerability_url(options[:project], vulnerability.id)
      end

      expose :severity, documentation: { type: 'String' }

      private

      def vulnerability_url(project, id)
        ::Gitlab::Routing.url_helpers.project_security_vulnerability_url(project, id)
      end
    end
  end
end
