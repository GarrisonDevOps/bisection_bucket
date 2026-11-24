# frozen_string_literal: true

module Devfile
  # Gem::Platform.local.cpu can return a varied arch depending on the distribution,
  # but they still refer to the same arch
  RUBY_CPU_TO_GOARCH = {
    'x86_64' => 'amd64',
    'aarch64' => 'arm64',
    'amd64' => 'amd64',
    'arm64' => 'arm64',
    'universal' => 'arm64'
    # This exist because if Rosetta is enabled on mac, it means both arm and amd64 bianries
    # can be run so the gem lib sets the CPU as "universal".
    # see: https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
  }.freeze
end
