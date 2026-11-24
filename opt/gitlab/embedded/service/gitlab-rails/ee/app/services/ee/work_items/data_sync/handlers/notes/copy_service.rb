# frozen_string_literal: true

module EE
  module WorkItems
    module DataSync
      module Handlers
        module Notes
          module CopyService
            extend ::Gitlab::Utils::Override

            override :build_description_version_attributes
            def build_description_version_attributes(description_version, description_version_ids_map)
              super.tap do |attrs|
                attrs['epic_id'] = nil
              end
            end
          end
        end
      end
    end
  end
end
