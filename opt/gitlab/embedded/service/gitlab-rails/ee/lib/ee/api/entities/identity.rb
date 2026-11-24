# frozen_string_literal: true

module EE
  module API
    module Entities
      module Identity
        extend ActiveSupport::Concern

        prepended do
          expose :saml_provider_id,
            documentation: { type: 'Integer', desc: 'ID of the SAML provider for a `group_saml` identity.' }
        end
      end
    end
  end
end
