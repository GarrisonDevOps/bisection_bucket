# frozen_string_literal: true

module EE
  module Gitlab
    module GlobalAnonymousId
      extend ActiveSupport::Concern

      class_methods do
        def self_managed_instance_identifier
          if License.current&.trial?
            instance_uuid
          else
            instance_id
          end
        end
      end
    end
  end
end
