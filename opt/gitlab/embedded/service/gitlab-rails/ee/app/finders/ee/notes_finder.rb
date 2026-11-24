# frozen_string_literal: true

module EE
  module NotesFinder
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    # rubocop:disable Gitlab/ModuleWithInstanceVariables
    override :noteables_for_type
    def noteables_for_type(noteable_type)
      case noteable_type
      when 'wiki_page/meta'
        return WikiPage::Meta.where(project_id: @project&.id, namespace_id: @params[:group_id]) # rubocop: disable CodeReuse/ActiveRecord
      when 'epic'
        return EpicsFinder.new(@current_user, group_id: @params[:group_id])
      when 'vulnerability'
        return ::Security::VulnerabilityReadsFinder.new(@project)
      end

      super
    end
    # rubocop:enable Gitlab/ModuleWithInstanceVariables

    override :notes_on_target
    def notes_on_target
      if target.respond_to?(:related_notes)
        target.related_notes
      elsif target.is_a?(::Vulnerabilities::Read)
        target.vulnerability.notes
      else
        target.notes
      end
    end
  end
end
