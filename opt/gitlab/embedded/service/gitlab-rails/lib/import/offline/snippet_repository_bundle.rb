# frozen_string_literal: true

module Import
  module Offline
    module SnippetRepositoryBundle
      BATCH_SIZE = 1000

      class << self
        # Snippet IDs differ between instances, so bundles are named by title and created_at, cut to
        # the milliseconds the NDJSON keeps. Description and updated_at are excluded because they can
        # change between the NDJSON export and the snippet repositories export.
        def filename_for(snippet)
          filename_from(snippet.title, snippet.created_at)
        end

        # Shared title + creation millisecond means one filename; both sides skip these snippets.
        # rubocop:disable CodeReuse/ActiveRecord -- query is specific to bundle naming
        def ambiguous_filenames(portable)
          counts = Hash.new(0)

          portable.snippets.each_batch(of: BATCH_SIZE) do |batch|
            batch.pluck(:title, :created_at).each do |title, created_at|
              counts[filename_from(title, created_at)] += 1
            end
          end

          counts.each_with_object(Set.new) { |(filename, count), set| set << filename if count > 1 }
        end
        # rubocop:enable CodeReuse/ActiveRecord

        private

        def filename_from(title, created_at)
          key = [title, created_at.utc.floor(3).iso8601(3)].join("\u0000")

          "#{Digest::SHA256.hexdigest(key)}.bundle"
        end
      end
    end
  end
end
