# frozen_string_literal: true

module WorkItems
  module Statuses
    class Finder
      attr_reader :namespace, :params, :current_user

      def initialize(namespace, params = {}, current_user = nil)
        @namespace = namespace
        @params = params
        @current_user = current_user
      end

      def execute
        result = if params.key?('status_id')
                   find_status_by_id
                 elsif params.key?('name')
                   name = params['name']
                   find_status_by_name(name).presence || find_status_without_quotes(name)
                 end

        Array(result)
      end

      def find_single_status
        execute.first
      end

      private

      # Custom statuses are only stored on the root ancestor namespace, so we
      # always look there to ensure subgroups and project namespaces inherit
      # the custom statuses defined at the root group level.
      def root_namespace
        namespace&.root_ancestor
      end

      # A namespace exclusively uses either custom or system-defined statuses.
      # Once converted to custom statuses, system-defined ones are replaced,
      # so checking root_namespace.custom_statuses.exists? is sufficient to
      # determine which model to query.
      def find_status_by_id
        if root_namespace&.custom_statuses&.exists?
          ::WorkItems::Statuses::Custom::Status
            .in_namespace(root_namespace)
            .find_by_id(params['status_id'])
        else
          ::WorkItems::Statuses::SystemDefined::Status
            .find_by(id: params['status_id'].to_i) # rubocop: disable CodeReuse/ActiveRecord -- this is a fixed model
        end
      end

      def find_status_without_quotes(name)
        return unless name.include?('"')
        return unless name.start_with?('"') && name.end_with?('"') && name.length > 2

        # Remove only leading and trailing quotes, not quotes within the name and
        # avoid regexp usage and ReDoS attacks with this approach.
        find_status_by_name(name[1..-2])
      end

      def find_status_by_name(name)
        return [] if name.blank?

        namespace ? find_status_in_namespace(name) : find_statuses_across_namespaces(name)
      end

      def find_status_in_namespace(name)
        status = if root_namespace&.custom_statuses&.exists?
                   ::WorkItems::Statuses::Custom::Status.find_by_namespace_and_name(root_namespace, name)
                 else
                   ::WorkItems::Statuses::SystemDefined::Status.find_by_name(name)
                 end

        Array(status)
      end

      def find_statuses_across_namespaces(name)
        return [] unless current_user

        group_ids = current_user.authorized_root_ancestor_ids
        return [] if group_ids.empty?

        custom_statuses = ::WorkItems::Statuses::Custom::Status.find_by_name_across_namespaces(name, group_ids)

        statuses = custom_statuses.to_a

        system_defined_status = ::WorkItems::Statuses::SystemDefined::Status.find_by_name(name)
        statuses << system_defined_status if system_defined_status

        statuses
      end
    end
  end
end
