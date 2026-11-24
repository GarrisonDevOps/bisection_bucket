# frozen_string_literal: true

module Search
  module Zoekt
    class QueryBuilder
      FEATURE = 'repository'

      def self.build(...)
        new(...).build
      end

      def initialize(query:, options: {})
        @query = query
        # allow extra_options to overwrite base_options
        @options = ::Gitlab::Utils.deep_indifferent_access(options.merge(base_options.merge(extra_options)))
      end

      def build
        raise NotImplementedError
      end

      private

      attr_reader :query, :options, :auth

      def current_user
        options[:current_user]
      end

      def group_id
        @group_id ||= options[:group_id]
      end

      def project_id
        @project_id ||= options[:project_id]
      end

      def group_ids
        [group_id].compact
      end

      def project_ids
        [project_id].compact
      end

      def filters
        options[:filters] || {}
      end

      def base_options
        {
          features: FEATURE
        }
      end

      # Subclasses should override this method to provide additional options to builder
      def extra_options
        {}
      end
    end
  end
end
