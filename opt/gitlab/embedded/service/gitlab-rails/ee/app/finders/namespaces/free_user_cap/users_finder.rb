# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class UsersFinder < ::Namespaces::BilledUsersFinder
      def self.count(group, limit)
        instance = new(group, limit)
        instance.execute
        instance.count
      end

      def initialize(group, limit)
        @group = group
        @limit = limit
        @ids = { user_ids: Set.new }
        @exclude_guests = false
      end

      def count
        ids.transform_values(&:count)
      end

      private

      attr_reader :limit

      def calculate_user_ids(method_name, hash_key)
        return if ids[:user_ids].count >= limit

        user_ids = fetch_user_ids(method_name) do |scope|
          scope.limit(limit)
        end

        @ids[hash_key] = user_ids
        @ids[:user_ids].merge(user_ids)
      end
    end
  end
end
