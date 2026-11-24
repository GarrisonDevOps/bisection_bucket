# frozen_string_literal: true

module EE
  module Gitlab
    module Database
      module MigrationHelpers
        module RestrictGitlabSchema
          extend ::Gitlab::Utils::Override

          UnknownGeoSiteError = Class.new(StandardError)

          # A Geo secondary fed by logical replication receives the primary's data changes, so
          # running a data migration here as well would collide with the replicated rows.
          override :exec_migration
          def exec_migration(conn, direction)
            return super unless data_arrives_through_logical_replication?(conn)

            say "The migration is skipped since this database is a Geo secondary that receives " \
              "data changes from the primary through logical replication."
          end

          private

          # Errors propagate on purpose: a check that cannot be answered on a subscriber aborts the
          # migration instead of letting its data changes collide with the replicated rows.
          def data_arrives_through_logical_replication?(conn)
            return false if allowed_gitlab_schemas.blank? || unmatched_schemas.any?
            return false if ::Gitlab::Geo::LogicalReplication.subscription_names(conn).empty?

            # GeoNode lives on the main database.
            with_restored_connection_stack do
              node = ::GeoNode.current_node

              unless node
                raise UnknownGeoSiteError, "This database has a logical replication subscription, but " \
                  "#{::GeoNode.current_node_name.inspect} does not match a Geo site. Fix the Geo site name first."
              end

              node.secondary?
            end
          end
        end
      end
    end
  end
end
