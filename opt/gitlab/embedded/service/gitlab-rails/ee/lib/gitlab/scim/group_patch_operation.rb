# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupPatchOperation
      ADD_OPERATION = 'add'
      REMOVE_OPERATION = 'remove'
      REPLACE_OPERATION = 'replace'
      MEMBERS_ATTRIBUTE = 'members'
      DISPLAY_NAME_ATTRIBUTE = 'displayname'
      EXTERNAL_ID_ATTRIBUTE = 'externalid'
      MEMBERS_FILTER_PATH_PREFIX = 'members['
      MEMBER_FILTER_PATH_REGEX = /\Amembers\[value\s+eq\s+"([^"]+)"\]\z/i

      def initialize(operation)
        @op = operation[:op].to_s.downcase
        @original_path = operation[:path].to_s
        @path = @original_path.downcase
        @value = operation[:value]
      end

      def add?
        op == ADD_OPERATION
      end

      def remove?
        op == REMOVE_OPERATION
      end

      def replace?
        op == REPLACE_OPERATION
      end

      def changes_members?
        return path.start_with?(MEMBERS_ATTRIBUTE) if path.present?

        members_key.present?
      end

      def supported_filter_path?
        return true unless members_filter_path?

        remove? && filter_members.present?
      end

      def remove_without_path?
        remove? && path.empty?
      end

      def removes_all_members?
        remove? && members_path? && value.nil?
      end

      def full_member_sync?
        (replace? && changes_members?) || removes_all_members?
      end

      def members
        return value if members_path?
        return members_from_value if path.empty?

        filter_members if remove?
      end

      def valid_members?
        return true unless changes_members?
        return true if removes_all_members?

        members.is_a?(Array) && members.all? { |member| valid_member?(member) }
      end

      def member_extern_uids
        return [] unless members.is_a?(Array) && valid_members?

        members.filter_map { |member| member[:value] }
      end

      def display_name
        attribute_value(DISPLAY_NAME_ATTRIBUTE)
      end

      def external_id
        attribute_value(EXTERNAL_ID_ATTRIBUTE)
      end

      private

      attr_reader :op, :path, :value

      def members_path?
        path == MEMBERS_ATTRIBUTE
      end

      def valid_member?(member)
        member.is_a?(Hash) && member[:value].is_a?(String) && member[:value].present?
      end

      def members_filter_path?
        path.start_with?(MEMBERS_FILTER_PATH_PREFIX)
      end

      def filter_members
        extern_uid = @original_path.match(MEMBER_FILTER_PATH_REGEX)&.captures&.first
        [{ value: extern_uid }] if extern_uid
      end

      def members_from_value
        key = members_key
        value[key] if key
      end

      def members_key
        value_key(MEMBERS_ATTRIBUTE)
      end

      def attribute_value(attribute)
        return if remove?
        return value if path == attribute
        return unless path.empty?

        key = value_key(attribute)
        value[key] if key
      end

      def value_key(attribute)
        return unless value.is_a?(Hash)

        value.keys.find { |key| key.to_s.casecmp?(attribute) }
      end
    end
  end
end
