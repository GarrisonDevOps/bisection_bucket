# frozen_string_literal: true

module Cd
  module DeployDrivers
    # Not a Driver subclass: the two manifests share no keys and an orchestrator binds to
    # no environment, so the file plumbing below is duplicated deliberately.
    class Orchestrator
      def self.for_gem(gem_name)
        new(root: Gem.loaded_specs.fetch(gem_name).gem_dir)
      end

      def initialize(root:)
        @root = root
      end

      def flow_definition_schema
        @flow_definition_schema ||= read_json(manifest.dig('configuration', 'flow_definition'))
      end

      # driver_scripts - Hash of { gem name => deploy fragment }
      def assemble(driver_scripts:)
        ::Gitlab::Cd::Driver::Orchestration.assemble(driver_scripts: driver_scripts)
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
