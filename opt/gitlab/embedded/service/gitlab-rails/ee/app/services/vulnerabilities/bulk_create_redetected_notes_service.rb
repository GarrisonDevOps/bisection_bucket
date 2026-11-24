# frozen_string_literal: true

module Vulnerabilities
  class BulkCreateRedetectedNotesService
    include Gitlab::Utils::StrongMemoize

    def initialize(vulnerabilities_data)
      @vulnerabilities_data = vulnerabilities_data
    end

    attr_reader :vulnerabilities_data

    def execute
      Note.transaction do
        results = Note.insert_all!(system_note_attributes, returning: %w[id created_at updated_at])
        SystemNoteMetadata.insert_all!(system_note_metadata_attributes(results))
      end
    end

    private

    def system_note_attributes
      vulnerabilities_data.filter_map do |data|
        pipeline = pipelines[data[:pipeline_id]]

        next if pipeline.blank?

        {
          noteable_type: "Vulnerability",
          noteable_id: data[:vulnerability_id],
          author_id: pipeline.user_id,
          project_id: pipeline.project_id,
          note: comment(pipeline),
          system: true,
          created_at: data[:timestamp],
          updated_at: data[:timestamp]
        }
      end
    end

    def pipelines
      # rubocop:disable CodeReuse/ActiveRecord -- Context specific
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- Array#pluck
      ids = vulnerabilities_data.pluck(:pipeline_id).uniq
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      Ci::Pipeline.preload({ project: [{ namespace: [:route] }] }).id_in(ids).index_by(&:id)
      # rubocop:enable CodeReuse/ActiveRecord -- Context specific
    end
    strong_memoize_attr :pipelines

    def system_note_metadata_attributes(results)
      results.map do |row|
        {
          note_id: row['id'],
          action: 'vulnerability_detected',
          created_at: row['created_at'],
          updated_at: row['updated_at']
        }
      end
    end

    def comment(pipeline)
      pipeline_link = pipeline_reference(pipeline)

      format(
        s_("Vulnerabilities|changed vulnerability status to Needs Triage " \
          "because it was redetected in pipeline %{pipeline_link}"),
        { pipeline_link: pipeline_link }
      )
    end

    def pipeline_reference(pipeline)
      url = Gitlab::UrlBuilder.build(pipeline)

      "[#{pipeline.id}](#{url})"
    end
  end
end
