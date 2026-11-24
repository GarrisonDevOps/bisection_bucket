# frozen_string_literal: true

module WorkItems
  module Statuses
    module SystemDefined
      module Templates
        class Status
          include Gitlab::Utils::StrongMemoize

          attr_accessor :lifecycle_template, :system_defined_status

          delegate :namespace, to: :lifecycle_template

          def initialize(lifecycle_template:, system_defined_status:)
            @lifecycle_template = lifecycle_template
            @system_defined_status = system_defined_status
          end

          # Template GIDs don't need to be resolvable by Rails
          # but we need an ID so Apollo can properly handle it
          def to_global_id
            encoded_name = CGI.escape(name)
            GlobalID.parse("gid://gitlab/#{self.class.name}/#{encoded_name}")
          end

          def name
            system_defined_status.name
          end

          # Merge attributes if custom status exists
          def color
            custom_status&.color || system_defined_status.color
          end

          # Be explicit here because no description is also valid
          def description
            custom_status ? custom_status.description : system_defined_status.description
          end

          # Unlikely that the category ever is different, but possible:
          # Transition from system-defined status to custom status and rename,
          # later create new status with the name of the system-defined status in another category.
          def category
            custom_status&.category || system_defined_status.category.to_s
          end

          def icon_name
            custom_status&.icon_name || system_defined_status.icon_name
          end

          private

          def custom_status
            lifecycle_template.custom_statuses_by_name[system_defined_status.name]
          end
          strong_memoize_attr :custom_status
        end
      end
    end
  end
end
