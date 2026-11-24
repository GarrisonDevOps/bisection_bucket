# frozen_string_literal: true

module API
  module Entities
    class Release < BasicReleaseDetails
      include ::API::Helpers::Presentable

      expose :description_html, if: ->(_, options) { options[:include_html_description] } do |entity|
        MarkupHelper.markdown_field(entity, :description, current_user: options[:current_user])
      end
      expose :author, using: Entities::UserBasic, if: ->(release, _) { release.author.present? }
      expose :commit, using: Entities::Commit, if: ->(_, _) { can_read_code? }
      expose :milestones,
        using: Entities::MilestoneWithStats,
        documentation: { is_array: true },
        if: ->(release, _) { release.milestones.present? && can_read_milestone? } do |release, _|
        release.milestones.order_by_dates_and_title
      end

      expose :commit_path,
        documentation: { type: 'String', example: '/root/app/commit/588440f66559714280628a4f9799f0c4eb880a4a' },
        expose_nil: false
      expose :tag_path, documentation: { type: 'String', example: '/root/app/-/tags/v1.0' }, expose_nil: false

      expose :assets do
        expose :assets_count, documentation: { type: 'Integer', example: 2 }, as: :count
        expose :sources, using: Entities::Releases::Source, if: ->(_, _) { can_read_code? }, documentation: { is_array: true }
        expose :sorted_links, as: :links, using: Entities::Releases::Link, documentation: { is_array: true }
      end
      expose :evidences, using: Entities::Releases::Evidence, expose_nil: false, if: ->(_, _) { can_read_code? }, documentation: { is_array: true }
      expose :_links, documentation: { type: 'Hash', desc: 'Links of the release.' } do
        expose :closed_issues_url, expose_nil: false,
          documentation: { type: 'String', desc: "HTTP URL of the release's closed issues." }
        expose :closed_merge_requests_url, expose_nil: false,
          documentation: { type: 'String', desc: "HTTP URL of the release's closed merge requests." }
        expose :edit_url, expose_nil: false,
          documentation: { type: 'String', desc: "HTTP URL of the release's edit page." }
        expose :merged_merge_requests_url, expose_nil: false,
          documentation: { type: 'String', desc: "HTTP URL of the release's merged merge requests." }
        expose :opened_issues_url, expose_nil: false,
          documentation: { type: 'String', desc: "HTTP URL of the release's open issues." }
        expose :opened_merge_requests_url, expose_nil: false,
          documentation: { type: 'String', desc: "HTTP URL of the release's open merge requests." }
        expose :self_url, as: :self, expose_nil: false,
          documentation: { type: 'String', desc: 'HTTP URL of the release.' }
      end
      expose :warnings, if: ->(_, options) { options[:warnings].present? },
        documentation: {
          type: 'String', is_array: true,
          example: ['No evidence was collected for this release.']
        } do |_, options|
        options[:warnings]
      end

      private

      def can_read_code?
        Ability.allowed?(options[:current_user], :read_code, object.project)
      end

      def can_read_milestone?
        Ability.allowed?(options[:current_user], :read_milestone, object.project)
      end
    end
  end
end
