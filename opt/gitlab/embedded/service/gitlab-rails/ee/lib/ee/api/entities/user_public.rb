# frozen_string_literal: true

module EE
  module API
    module Entities
      module UserPublic
        extend ActiveSupport::Concern

        prepended do
          expose :shared_runners_minutes_limit,
            documentation: { type: 'Integer', desc: 'Shared runners minutes limit of the user.' }
          expose :extra_shared_runners_minutes_limit,
            documentation: { type: 'Integer', desc: 'Extra shared runners minutes limit of the user.' }
          expose :scim_identities, using: ::API::Entities::ScimIdentity,
            documentation: { type: 'API::Entities::ScimIdentity', is_array: true,
                             desc: 'SCIM identities of the user.' }

          private

          def scim_identities
            object.instance_scim_identities + object.group_scim_identities
          end
        end
      end
    end
  end
end
