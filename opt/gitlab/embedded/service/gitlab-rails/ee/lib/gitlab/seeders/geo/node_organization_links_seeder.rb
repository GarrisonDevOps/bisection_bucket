# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- Seeder utility whose purpose is to create and look up records directly
module Gitlab
  module Seeders
    module Geo
      # Never creates geo_nodes: one geo_nodes row makes the instance
      # consider Geo enabled, which would change the behaviour of every
      # fixture that runs after this one.
      class NodeOrganizationLinksSeeder
        LINKS_PER_NODE = 3

        def seed!
          node = ::GeoNode.order(:id).first
          return warn "\nSkipping geo_node_organization_links: no geo_nodes records" unless node

          organizations = ::Organizations::Organization.order(:id).limit(LINKS_PER_NODE)

          rows = missing_link_rows(node, organizations)
          return if rows.empty?

          ::Geo::GeoNodeOrganizationLink.insert_all!(rows)
          print '.'
        end

        private

        def missing_link_rows(node, organizations)
          existing = ::Geo::GeoNodeOrganizationLink
            .where(geo_node_id: node.id)
            .pluck(:organization_id)
            .to_set

          now = Time.current

          organizations.reject { |organization| existing.include?(organization.id) }.map do |organization|
            {
              geo_node_id: node.id,
              organization_id: organization.id,
              created_at: now,
              updated_at: now
            }
          end
        end
      end
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
