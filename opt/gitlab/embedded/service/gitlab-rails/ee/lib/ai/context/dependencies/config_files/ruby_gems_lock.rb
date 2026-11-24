# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class RubyGemsLock < Base
          def self.file_name_glob
            'Gemfile.lock'
          end

          def self.lang_name
            'Ruby'
          end

          private

          ### Example format:
          #
          # GEM
          # remote: https://rubygems.org/
          # specs:
          #   bcrypt (3.1.20)
          #   logger (1.5.3)
          #
          def extract_libs
            parser = Bundler::LockfileParser.new(content)

            parser.specs.map do |spec|
              Lib.new(name: spec.name, version: spec.version.to_s)
            end
          rescue Bundler::LockfileError => e
            # Bundler uses the server's default lockfile name in the error message, but we shouldn't
            # use it here since we are actually parsing lockfile content from a different repository.
            message = e.message.split("\n").first.to_s.gsub(Bundler.default_lockfile.basename.to_s, 'gem lockfile')
            raise ParsingErrors::DeserializationException, message
          end
        end
      end
    end
  end
end
