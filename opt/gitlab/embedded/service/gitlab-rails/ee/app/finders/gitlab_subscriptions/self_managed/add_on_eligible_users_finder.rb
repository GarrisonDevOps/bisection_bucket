# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class AddOnEligibleUsersFinder
      attr_reader :add_on_type, :add_on_purchase_id, :filter_options, :sort

      def initialize(add_on_type:, add_on_purchase_id: nil, filter_options: {}, sort: nil)
        @add_on_type = add_on_type
        @add_on_purchase_id = add_on_purchase_id
        @filter_options = filter_options
        @sort = sort
      end

      def execute
        return ::User.none unless GitlabSubscriptions::SystemDefined::AddOn::DUO_ADD_ONS.include?(add_on_type)

        users = ::User.active.without_bots.without_ghosts

        users = filter_assigned_users(users) if valid_filter_criteria?

        filter_options[:search_term] ? users.search(filter_options[:search_term]) : users.sort_by_attribute(sort)
      end

      private

      def valid_filter_criteria?
        return false unless add_on_purchase_id.present?

        [true, false].include? filter_options[:filter_by_assigned_seat]
      end

      def filter_assigned_users(collection)
        assignments = GitlabSubscriptions::UserAddOnAssignment.for_active_add_on_purchase_ids(add_on_purchase_id)

        if filter_options[:filter_by_assigned_seat]
          User.id_in(assignments.select(:user_id))
        else
          collection.id_not_in(assignments.select(:user_id))
        end
      end
    end
  end
end
