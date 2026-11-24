# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountEventStreamingDestinationsMetric < DatabaseMetric
          operation :count

          relation do |options|
            base_relation = AuditEvents::ExternalAuditEventDestination

            if options&.[](:with_assigned_compliance_frameworks)
              subquery = Namespace
                .joins("JOIN projects ON projects.namespace_id = namespaces.id")
                .joins("JOIN project_compliance_framework_settings " \
                  "ON project_compliance_framework_settings.project_id = projects.id")
                .where(type: 'Group')
                .where.not(project_compliance_framework_settings: { framework_id: nil })
                .where(Namespace.arel_table[:id].eq(base_relation.arel_table[:namespace_id]))

              base_relation.where_exists subquery
            else
              base_relation
            end
          end
        end
      end
    end
  end
end
