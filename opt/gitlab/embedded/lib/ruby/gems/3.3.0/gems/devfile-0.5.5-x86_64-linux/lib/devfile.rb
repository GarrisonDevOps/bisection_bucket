# frozen_string_literal: true

require 'open3'
require_relative 'ruby_cpu_to_go_arch'

# Module that works with the Devfile standard
module Devfile
  class CliError < StandardError; end
  class UnsupportedPlatform < StandardError; end

  # Set of services to parse a devfile and output k8s manifests
  class Parser
    DEVFILE_GEMSPEC = Gem.loaded_specs['devfile']
    ARCH = RUBY_CPU_TO_GOARCH[Gem::Platform.local.cpu] || Gem::Platform.local.cpu
    SYSTEM_PLATFORM = "#{ARCH}-#{Gem::Platform.local.os}"
    FILE_PATH = File.expand_path("./../out/devfile-#{SYSTEM_PLATFORM}", File.dirname(__FILE__))

    class << self
      def get_deployment(devfile, name, namespace, labels, annotations, replicas)
        call('deployment', devfile, name, namespace, labels, annotations, replicas)
      end

      def get_service(devfile, name, namespace, labels, annotations)
        call('service', devfile, name, namespace, labels, annotations)
      end

      def get_ingress(devfile, name, namespace, labels, annotations, domain_template, ingress_class)
        call('ingress', devfile, name, namespace, labels, annotations, domain_template, ingress_class)
      end

      def get_pvc(devfile, name, namespace, labels, annotations)
        call('deployment', devfile, name, namespace, labels, annotations)
      end

      def get_all(devfile, name, namespace, labels, annotations, replicas, domain_template, ingress_class)
        call('all', devfile, name, namespace, labels, annotations, replicas, domain_template, ingress_class)
      end

      def flatten(devfile)
        call('flatten', devfile)
      end

      private

      def call(*cmd)
        raise_if_unsupported_system_platform! if ruby_platform?

        stdout, stderr, status = Open3.capture3({}, FILE_PATH, *cmd.map(&:to_s))
        raise(CliError, stderr) unless status.success?

        stdout
      end

      def ruby_platform?
        DEVFILE_GEMSPEC && DEVFILE_GEMSPEC.platform == 'ruby'
      end

      def raise_if_unsupported_system_platform!
        return if %w[amd64-linux amd64-darwin arm64-linux arm64-darwin].include?(SYSTEM_PLATFORM)

        err_msg = "Unsupported platform:#{SYSTEM_PLATFORM}, devfile-gem only supports " \
           "os: darwin/linux and architectures: amd64/arm64 for 'ruby' platform only"
        raise UnsupportedPlatform, err_msg
      end
    end
  end
end
