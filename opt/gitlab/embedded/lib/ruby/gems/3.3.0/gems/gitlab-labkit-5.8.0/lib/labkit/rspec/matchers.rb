# frozen_string_literal: true

# RSpec matchers loader for Labkit
#
# This file loads all available RSpec matchers for Labkit.
# It must be explicitly required in your test setup.

raise LoadError, "RSpec is not loaded. Please require 'rspec' before requiring 'labkit/rspec/matchers'" unless defined?(RSpec)

require_relative 'matchers/user_experience_matchers'
