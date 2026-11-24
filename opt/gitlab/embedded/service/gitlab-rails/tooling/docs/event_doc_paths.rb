# frozen_string_literal: true

module Docs
  # EventStore event docs sit in the same code root as the event class:
  # data/events/ for app/events/ and ee/app/events/, and
  # domains/<name>/data/events/ for both halves of a domain.
  module EventDocPaths
    DOC_GLOB = '{,domains/*/}data/events/**/*.yml'
    EVENT_PATH = %r{(?<![^/])(?<domain>domains/[^/]+/)?(?:ee/)?app/events/(?<rest>.+)\.rb\z}
    DOC_PATH = %r{data/events/(?<rest>.+)\z}

    # Returns the doc path for an event class file, keeping any root prefix of the input.
    def self.doc_path_for(event_file)
      match = EVENT_PATH.match(event_file)

      "#{event_file[0...match.begin(0)]}#{match[:domain]}data/events/#{match[:rest]}.yml"
    end

    # Returns the doc path relative to its data/events/ directory.
    def self.relative_doc_path(doc_file)
      doc_file[DOC_PATH, :rest]
    end

    def self.doc_files(root)
      Dir.glob(DOC_GLOB, base: root.to_s).sort.map { |path| File.join(root.to_s, path) }
    end
  end
end
