# frozen_string_literal: true

# Provides access to pull mirror attributes
module Repositories
  module PullMirrors
    class Attributes
      ALLOWED_ATTRIBUTES = %i[
        mirror
        import_url
        username_only_import_url
        mirror_trigger_builds
        only_mirror_protected_branches
        mirror_overwrites_diverged_branches
        import_data_attributes
        mirror_branch_regex
      ].freeze

      def initialize(attrs)
        @attrs = attrs
      end

      def allowed
        attrs.slice(*keys).tap do |params|
          # It's not possible to set both "only protected branches" and "branches that match regex" options
          # at the same time. If user provides a regexp for branches it should disable "only protected branches"
          # configuration and vice versa.
          params[:only_mirror_protected_branches] = false if params[:mirror_branch_regex].present?
          params[:mirror_branch_regex] = nil if params[:only_mirror_protected_branches]
        end
      end

      def keys
        ALLOWED_ATTRIBUTES
      end

      private

      attr_reader :attrs
    end
  end
end
