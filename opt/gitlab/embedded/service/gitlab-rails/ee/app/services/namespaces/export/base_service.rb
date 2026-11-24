# frozen_string_literal: true

module Namespaces
  module Export
    class BaseService < ::BaseContainerService
      def execute
        return service_not_available unless Ability.allowed?(current_user, :export_group_memberships, container)

        ServiceResponse.success(payload: csv_builder.render)
      end

      private

      def csv_builder
        @csv_builder ||= CsvBuilder.new(data, header_to_value_hash)
      end

      def member_source(member)
        return 'Direct member' if member.source == container
        return 'Inherited member' if container.ancestor_ids.include?(member.source_id)

        'Descendant member'
      end

      def service_not_available
        ServiceResponse.error(message: 'Not available')
      end
    end
  end
end
