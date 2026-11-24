# frozen_string_literal: true

module Cd
  module DeployDrivers
    class Driver
      def self.for_gem(gem_name)
        new(gem_name: gem_name, root: Gem.loaded_specs.fetch(gem_name).gem_dir)
      end

      def initialize(gem_name:, root:)
        @gem_name = gem_name
        @root = root
      end

      attr_reader :gem_name

      def environment_schema
        @environment_schema ||= read_json(manifest.dig('configuration', 'environment'))
      end

      def application_environment_schema
        @application_environment_schema ||= read_json(manifest.dig('configuration', 'service_environment'))
      end

      def steps_schema
        @steps_schema ||= read_json(manifest.dig('steps', 'supported'))
      end

      # Not runnable alone: needs the orchestration engine concatenated in front of it.
      # Read as UTF-8, not binary: assemble joins this with its own UTF-8 main.star, which
      # Ruby refuses once both carry non-ASCII bytes, and re-tags the joined program binary.
      def deploy_fragment
        @deploy_fragment ||= File.read(File.join(root, manifest.dig('scripts', 'deploy')))
      end

      private

      attr_reader :root

      def manifest
        @manifest ||= read_json('manifest.json')
      end

      def read_json(relative_path)
        Gitlab::Json::SafeParser.parse(File.read(File.join(root, relative_path)))
      end
    end
  end
end
