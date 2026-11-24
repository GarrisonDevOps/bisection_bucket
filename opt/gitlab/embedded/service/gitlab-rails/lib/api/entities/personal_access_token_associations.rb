# frozen_string_literal: true

module API
  module Entities
    class PersonalAccessTokenAssociations < Grape::Entity
      expose :groups, using: ::API::Entities::GroupAssociationDetails,
        documentation: { type: 'API::Entities::GroupAssociationDetails', is_array: true }
      expose :projects, using: ::API::Entities::ProjectAssociationDetails,
        documentation: { type: 'API::Entities::ProjectAssociationDetails', is_array: true }
    end
  end
end
