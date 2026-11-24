# frozen_string_literal: true

module Geo
  class GeoNodeOrganizationLink < ApplicationRecord
    belongs_to :geo_node, inverse_of: :organizations, optional: false
    belongs_to :organization, class_name: 'Organizations::Organization', optional: false

    validates :organization_id, uniqueness: { scope: [:geo_node_id] }
  end
end
