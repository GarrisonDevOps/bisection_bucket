# frozen_string_literal: true

module Search
  module Elastic
    module Filters
      class ConfidentialityFilterContext
        attr_reader :user, :filter_path, :confidential, :auth

        def initialize(options)
          @confidential = options[:confidential]
          @user = options[:current_user]
          @filter_path = options.fetch(:filter_path, [:query, :bool, :filter])
          @options = options
          @auth = ::Search::AuthorizationContext.new(user)
        end

        def confidential_only?
          confidential == true
        end

        def non_confidential_only?
          confidential == false
        end

        def confidential_filter_specified?
          confidential_only? || non_confidential_only?
        end

        def min_access_level_confidential
          options.fetch(:min_access_level_confidential)
        end

        def min_access_level_confidential_public_internal
          options.fetch(:min_access_level_confidential_public_internal)
        end

        def project_id_field
          @project_id_field ||= options.fetch(:project_id_field, Search::Elastic::Filters::PROJECT_ID_FIELD).to_sym
        end

        def traversal_ids_field
          @traversal_ids_field ||= options.fetch(:traversal_ids_prefix,
            Search::Elastic::Filters::TRAVERSAL_IDS_FIELD).to_sym
        end

        def confidential_field
          @confidential_field ||= options.fetch(:confidential_field, :confidential).to_sym
        end

        def author_id_field
          @author_id_field ||= options.fetch(:author_id_field, :author_id).to_sym
        end

        def assignee_id_field
          @assignee_id_field ||= options.fetch(:assignee_id_field, :assignee_id).to_sym
        end

        private

        attr_reader :options
      end
    end
  end
end
