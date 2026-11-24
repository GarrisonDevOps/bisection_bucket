# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    class Configuration
      attr_accessor :api_version, :api_prefix, :excluded_api_classes, :servers, :security_schemes, :info,
        :tag_overrides, :annotations, :coercer_mappings, :warnings,
        :cross_field_group_limit, :cross_field_messages, :schema_paths

      def initialize
        @api_prefix = "api"
        @api_version = "v1"
        @excluded_api_classes = []
        @info = nil

        @servers = []
        @security_schemes = []

        @tag_overrides = {}
        @annotations = {}
        @coercer_mappings = {}
        @warnings = false
        @schema_paths = []

        # Cross field validations
        # Allow custom descriptions for endpoints whose groups of cross-validated
        # params exceed cross_field_group_limit
        @cross_field_group_limit = 30
        @cross_field_messages = {}
      end
    end
  end
end
