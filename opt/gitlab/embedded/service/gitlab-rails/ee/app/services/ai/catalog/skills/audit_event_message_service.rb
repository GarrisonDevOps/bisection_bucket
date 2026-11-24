# frozen_string_literal: true

module Ai
  module Catalog
    module Skills
      class AuditEventMessageService < Items::BaseAuditEventMessageService
        private

        def item_type
          'skill'
        end

        def expected_schema_version
          # Update this when Ai::Catalog::ItemVersion::SKILL_SCHEMA_VERSION changes
          1
        end

        # Skills are published from the repository, not created through the catalog
        def create_messages
          []
        end

        def build_change_descriptions
          []
        end
      end
    end
  end
end
