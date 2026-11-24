# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Domains
        # Schema and data migrations are the least reversible thing most changes
        # can do: a dropped column or a lock held on a large table cannot be
        # rolled back by reverting the merge request. Scoped to schema and
        # database-layer changes on purpose. Query construction fails a
        # different way -- slow queries rather than lost data -- so it belongs
        # to a separate domain.
        module DatabaseMigration
          module_function

          def configuration
            {
              name: 'database_migration',
              severity: 'high',
              description: N_('RiskAssessment|Database schema, data migration, or database layer')
            }
          end
        end
      end
    end
  end
end
